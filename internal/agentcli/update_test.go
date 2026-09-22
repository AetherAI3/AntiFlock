package agentcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, directory, version string, sum string) string {
	t.Helper()
	manifest := ReleaseManifest{Document: ReleaseManifestSchema, Version: version, Artifacts: []ReleaseArtifact{{Name: "antiflock-agent", SHA256: sum}}, Signature: &ReleaseSignature{Type: "cosign-bundle-out-of-band", Verified: true}}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, version+".json")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeBinary(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestUpdateCheckReportsCurrentOrAvailable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "antiflock-agent")
	running := writeBinary(t, target, "binary-v1")
	current := writeManifest(t, root, "1.0.0", running)
	result, reason, code := UpdateCheck(target, current)
	if code != ExitOK || reason.Code != "AF-UPDATE-CURRENT" || !result.UpToDate || result.SignatureVerified {
		t.Fatalf("check current = %d %#v %#v", code, reason, result)
	}
	other := sha256.Sum256([]byte("binary-v2"))
	newer := writeManifest(t, root, "1.1.0", hex.EncodeToString(other[:]))
	result, reason, code = UpdateCheck(target, newer)
	if code != ExitDegraded || reason.Code != "AF-UPDATE-AVAILABLE" || result.UpToDate || result.ManifestVersion != "1.1.0" {
		t.Fatalf("check available = %d %#v %#v", code, reason, result)
	}
	if _, reason, code := UpdateCheck(target, filepath.Join(root, "missing.json")); code != ExitVerification || reason.Code != "AF-UPDATE-MANIFEST-INVALID" {
		t.Fatalf("missing manifest = %d %#v", code, reason)
	}
	bad := filepath.Join(root, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"document":"antiflock.release-manifest/v1","version":"1","artifacts":[{"name":"antiflock-agent","sha256":"nothex"}]}`), 0o644)
	if _, _, code := UpdateCheck(target, bad); code != ExitVerification {
		t.Fatalf("bad digest manifest exit = %d", code)
	}
	extra := filepath.Join(root, "extra.json")
	_ = os.WriteFile(extra, []byte(`{"document":"antiflock.release-manifest/v1","version":"1","artifacts":[{"name":"antiflock-agent","sha256":"`+running+`"}],"downloadUrl":"https://example.test"}`), 0o644)
	if _, _, code := UpdateCheck(target, extra); code != ExitVerification {
		t.Fatalf("unknown field manifest exit = %d", code)
	}
}

func TestUpdateApplyRefusesChecksumMismatchWithoutTouchingTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "antiflock-agent")
	writeBinary(t, target, "binary-v1")
	candidate := filepath.Join(root, "candidate")
	writeBinary(t, candidate, "binary-tampered")
	wanted := sha256.Sum256([]byte("binary-v2"))
	manifest := writeManifest(t, root, "1.1.0", hex.EncodeToString(wanted[:]))
	result, reason, code := UpdateApply(target, manifest, candidate)
	if code != ExitVerification || reason.Code != "AF-UPDATE-CHECKSUM-MISMATCH" || result.Applied {
		t.Fatalf("apply mismatch = %d %#v %#v", code, reason, result)
	}
	content, _ := os.ReadFile(target)
	if string(content) != "binary-v1" {
		t.Fatalf("target changed: %q", content)
	}
	if _, err := os.Lstat(target + ".previous"); err == nil {
		t.Fatal("backup created on refused update")
	}
	if _, err := os.Lstat(target + ".staging"); err == nil {
		t.Fatal("staging left behind on refused update")
	}
}

func TestUpdateApplyAndRollbackSwapAtomically(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "antiflock-agent")
	writeBinary(t, target, "binary-v1")
	candidate := filepath.Join(root, "candidate")
	sum := writeBinary(t, candidate, "binary-v2")
	manifest := writeManifest(t, root, "1.1.0", sum)
	result, reason, code := UpdateApply(target, manifest, candidate)
	if code != ExitOK || reason.Code != "AF-UPDATE-APPLIED" || !result.Applied || result.BackupPath != target+".previous" {
		t.Fatalf("apply = %d %#v %#v", code, reason, result)
	}
	content, _ := os.ReadFile(target)
	previous, _ := os.ReadFile(target + ".previous")
	if string(content) != "binary-v2" || string(previous) != "binary-v1" {
		t.Fatalf("after apply target=%q previous=%q", content, previous)
	}
	if info, _ := os.Lstat(target); info.Mode().Perm() != 0o755 {
		t.Fatalf("mode not preserved: %v", info.Mode())
	}
	if _, _, code := UpdateApply(target, manifest, candidate); code != ExitOK {
		t.Fatalf("re-apply of current version exit = %d", code)
	}
	result, reason, code = UpdateRollback(target)
	if code != ExitOK || reason.Code != "AF-UPDATE-ROLLED-BACK" || !result.RolledBack {
		t.Fatalf("rollback = %d %#v %#v", code, reason, result)
	}
	content, _ = os.ReadFile(target)
	previous, _ = os.ReadFile(target + ".previous")
	if string(content) != "binary-v1" || string(previous) != "binary-v2" {
		t.Fatalf("after rollback target=%q previous=%q", content, previous)
	}
	if _, err := os.Lstat(target + ".rollback"); err == nil {
		t.Fatal("rollback swap file left behind")
	}
}

func TestUpdateRefusesNonRegularTargets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	real := filepath.Join(root, "real")
	sum := writeBinary(t, real, "binary-v1")
	manifest := writeManifest(t, root, "1.0.0", sum)
	link := filepath.Join(root, "antiflock-agent")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, reason, code := UpdateCheck(link, manifest); code != ExitRefused || reason.Code != "AF-UPDATE-TARGET-NOT-REGULAR" {
		t.Fatalf("check symlink = %d %#v", code, reason)
	}
	if _, reason, code := UpdateApply(link, manifest, real); code != ExitRefused || reason.Code != "AF-UPDATE-TARGET-NOT-REGULAR" {
		t.Fatalf("apply symlink = %d %#v", code, reason)
	}
	if _, reason, code := UpdateRollback(link); code != ExitRefused || reason.Code != "AF-UPDATE-ROLLBACK-UNAVAILABLE" {
		t.Fatalf("rollback symlink = %d %#v", code, reason)
	}
	if _, reason, code := UpdateRollback(real); code != ExitRefused || reason.Code != "AF-UPDATE-ROLLBACK-UNAVAILABLE" {
		t.Fatalf("rollback without backup = %d %#v", code, reason)
	}
}
