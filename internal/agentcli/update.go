package agentcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReleaseManifestSchema identifies the release manifest document that
// update consumes. It is produced out of band (see docs/release-policy.md);
// this command never downloads anything.
const ReleaseManifestSchema = "antiflock.release-manifest/v1"

const (
	maximumManifestBytes = 256 << 10
	maximumBinaryBytes   = 512 << 20
	previousSuffix       = ".previous"
	stagingSuffix        = ".staging"
	agentArtifactName    = "antiflock-agent"
)

// ReleaseArtifact is one file in the manifest. Path is optional: when
// present it must be absolute and is used only for reporting.
type ReleaseArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// ReleaseSignature is a placeholder: provenance is verified with cosign
// against SHA256SUMS per docs/release-policy.md, outside this command.
// A manifest can therefore never claim to be verified on its own.
type ReleaseSignature struct {
	Type     string `json:"type"`
	Verified bool   `json:"verified"`
}

// ReleaseManifest is the input document of update --check / --from-file.
type ReleaseManifest struct {
	Document  string            `json:"document"`
	Version   string            `json:"version"`
	Artifacts []ReleaseArtifact `json:"artifacts"`
	Signature *ReleaseSignature `json:"signature,omitempty"`
}

// LoadReleaseManifest reads and validates a manifest file.
func LoadReleaseManifest(path string) (ReleaseManifest, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > maximumManifestBytes {
		return ReleaseManifest{}, errors.New("release manifest must be a bounded regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return ReleaseManifest{}, errors.New("read release manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest ReleaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ReleaseManifest{}, errors.New("release manifest is not valid JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ReleaseManifest{}, errors.New("release manifest contains trailing data")
	}
	if manifest.Document != ReleaseManifestSchema || !canonicalIdentifier(manifest.Version, 64) || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 32 {
		return ReleaseManifest{}, errors.New("release manifest document, version, or artifact list is invalid")
	}
	for _, artifact := range manifest.Artifacts {
		if !canonicalIdentifier(artifact.Name, 128) || !validSHA256(artifact.SHA256) {
			return ReleaseManifest{}, errors.New("release manifest artifact name or sha256 is invalid")
		}
	}
	return manifest, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

// AgentArtifact returns the manifest entry for this binary.
func (manifest ReleaseManifest) AgentArtifact() (ReleaseArtifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == agentArtifactName {
			return artifact, true
		}
	}
	return ReleaseArtifact{}, false
}

// UpdateResult is the update payload.
type UpdateResult struct {
	Mode              string `json:"mode"`
	Target            string `json:"target"`
	RunningSHA256     string `json:"runningSha256,omitempty"`
	ManifestVersion   string `json:"manifestVersion,omitempty"`
	ManifestSHA256    string `json:"manifestSha256,omitempty"`
	CandidateSHA256   string `json:"candidateSha256,omitempty"`
	UpToDate          bool   `json:"upToDate"`
	Applied           bool   `json:"applied"`
	RolledBack        bool   `json:"rolledBack"`
	BackupPath        string `json:"backupPath,omitempty"`
	SignatureVerified bool   `json:"signatureVerified"`
}

// FileSHA256 hashes a regular, non-symlink, bounded file.
func FileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > maximumBinaryBytes {
		return "", errors.New("file must be a bounded regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("open file for hashing")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumBinaryBytes+1)); err != nil {
		return "", errors.New("hash file")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// UpdateCheck compares the running binary against the manifest. Exit 0 when
// the binary matches, 7 when an update is available, 4 when the manifest is
// unusable, 6 when the target is not a regular file.
func UpdateCheck(target, manifestPath string) (UpdateResult, Reason, int) {
	result := UpdateResult{Mode: "check", Target: target}
	running, err := FileSHA256(target)
	if err != nil {
		return result, Reason{Code: "AF-UPDATE-TARGET-NOT-REGULAR", Message: "running binary is not a regular file; refusing"}, ExitRefused
	}
	result.RunningSHA256 = running
	manifest, err := LoadReleaseManifest(manifestPath)
	if err != nil {
		return result, Reason{Code: "AF-UPDATE-MANIFEST-INVALID", Message: err.Error()}, ExitVerification
	}
	artifact, ok := manifest.AgentArtifact()
	if !ok {
		return result, Reason{Code: "AF-UPDATE-MANIFEST-NO-AGENT", Message: "release manifest has no antiflock-agent artifact"}, ExitVerification
	}
	result.ManifestVersion, result.ManifestSHA256 = manifest.Version, artifact.SHA256
	result.SignatureVerified = false
	if running == artifact.SHA256 {
		result.UpToDate = true
		return result, Reason{Code: "AF-UPDATE-CURRENT", Message: "running binary matches the manifest"}, ExitOK
	}
	return result, Reason{Code: "AF-UPDATE-AVAILABLE", Message: "running binary differs from the manifest; apply with --from-file after verifying the artifact per docs/release-policy.md"}, ExitDegraded
}

// UpdateApply installs candidate over target when its sha256 matches the
// manifest. The swap is two renames in the target directory: target goes to
// target.previous, the staged copy becomes target. A checksum mismatch or a
// non-regular target refuses before anything is written.
func UpdateApply(target, manifestPath, candidate string) (UpdateResult, Reason, int) {
	result := UpdateResult{Mode: "apply", Target: target}
	targetInfo, err := os.Lstat(target)
	if err != nil || !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
		return result, Reason{Code: "AF-UPDATE-TARGET-NOT-REGULAR", Message: "running binary is not a regular file; refusing"}, ExitRefused
	}
	running, err := FileSHA256(target)
	if err != nil {
		return result, Reason{Code: "AF-UPDATE-TARGET-NOT-REGULAR", Message: "running binary could not be hashed; refusing"}, ExitRefused
	}
	result.RunningSHA256 = running
	manifest, err := LoadReleaseManifest(manifestPath)
	if err != nil {
		return result, Reason{Code: "AF-UPDATE-MANIFEST-INVALID", Message: err.Error()}, ExitVerification
	}
	artifact, ok := manifest.AgentArtifact()
	if !ok {
		return result, Reason{Code: "AF-UPDATE-MANIFEST-NO-AGENT", Message: "release manifest has no antiflock-agent artifact"}, ExitVerification
	}
	result.ManifestVersion, result.ManifestSHA256 = manifest.Version, artifact.SHA256
	candidateSum, err := FileSHA256(candidate)
	if err != nil {
		return result, Reason{Code: "AF-UPDATE-CANDIDATE-NOT-REGULAR", Message: "candidate file must be a bounded regular file"}, ExitVerification
	}
	result.CandidateSHA256 = candidateSum
	if candidateSum != artifact.SHA256 {
		return result, Reason{Code: "AF-UPDATE-CHECKSUM-MISMATCH", Message: "candidate sha256 does not match the release manifest; nothing was changed"}, ExitVerification
	}
	if running == candidateSum {
		result.UpToDate = true
		return result, Reason{Code: "AF-UPDATE-CURRENT", Message: "running binary already matches the manifest"}, ExitOK
	}
	staging := target + stagingSuffix
	_ = os.Remove(staging)
	if err := copyFile(candidate, staging, targetInfo.Mode().Perm()); err != nil {
		_ = os.Remove(staging)
		return result, Reason{Code: "AF-UPDATE-STAGE-FAILED", Message: "could not stage the candidate next to the running binary"}, ExitFailure
	}
	if staged, err := FileSHA256(staging); err != nil || staged != artifact.SHA256 {
		_ = os.Remove(staging)
		return result, Reason{Code: "AF-UPDATE-CHECKSUM-MISMATCH", Message: "staged copy does not match the release manifest; nothing was changed"}, ExitVerification
	}
	backup := target + previousSuffix
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		_ = os.Remove(staging)
		return result, Reason{Code: "AF-UPDATE-SWAP-FAILED", Message: "could not move the running binary aside"}, ExitFailure
	}
	if err := os.Rename(staging, target); err != nil {
		_ = os.Rename(backup, target)
		_ = os.Remove(staging)
		return result, Reason{Code: "AF-UPDATE-SWAP-FAILED", Message: "could not install the staged binary; previous binary restored"}, ExitFailure
	}
	result.Applied, result.BackupPath = true, backup
	return result, Reason{Code: "AF-UPDATE-APPLIED", Message: "binary replaced; restart the service to run the new version"}, ExitOK
}

// UpdateRollback swaps target.previous back into place. The current binary
// becomes target.previous so a rollback can itself be undone once.
func UpdateRollback(target string) (UpdateResult, Reason, int) {
	result := UpdateResult{Mode: "rollback", Target: target}
	backup := target + previousSuffix
	for _, path := range []string{target, backup} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return result, Reason{Code: "AF-UPDATE-ROLLBACK-UNAVAILABLE", Message: "both the running binary and " + previousSuffix + " must be regular files"}, ExitRefused
		}
	}
	swap := target + ".rollback"
	_ = os.Remove(swap)
	if err := os.Rename(target, swap); err != nil {
		return result, Reason{Code: "AF-UPDATE-SWAP-FAILED", Message: "could not move the running binary aside"}, ExitFailure
	}
	if err := os.Rename(backup, target); err != nil {
		_ = os.Rename(swap, target)
		return result, Reason{Code: "AF-UPDATE-SWAP-FAILED", Message: "could not restore the previous binary; running binary restored"}, ExitFailure
	}
	if err := os.Rename(swap, backup); err != nil {
		return result, Reason{Code: "AF-UPDATE-ROLLBACK-PARTIAL", Message: "previous binary restored but the replaced binary could not be kept as " + previousSuffix}, ExitDegraded
	}
	running, err := FileSHA256(target)
	if err == nil {
		result.RunningSHA256 = running
	}
	result.RolledBack, result.BackupPath = true, backup
	return result, Reason{Code: "AF-UPDATE-ROLLED-BACK", Message: "previous binary restored; restart the service"}, ExitOK
}

func copyFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, maximumBinaryBytes)); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, mode)
}

// ExecutablePath resolves the running binary without following a symlink
// further than os.Executable already does; it must be absolute.
func ExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("running executable path is unavailable")
	}
	return filepath.Clean(path), nil
}
