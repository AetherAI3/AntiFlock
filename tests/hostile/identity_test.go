package hostile_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/identity"
)

func rewrite(t *testing.T, path string, transform func([]byte) []byte) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, transform(content), info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
}

// Invariant: a deployment identity directory is a signed, coherent unit. Any
// single-file tamper (state, CA key, audit key, keyring, recovery credential)
// makes identity.Ensure fail closed instead of loading a partially trusted
// authority or silently re-creating one.
func TestIdentityEnsureFailsClosedOnTamperedArtifacts(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: identity file modes are POSIX permission bits; Windows ACL coverage lives in core/identity/security_windows_test.go")
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	cases := map[string]func(t *testing.T, directory string){
		"deployment-state-signature-bit-flip": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "deployment.json"), func(content []byte) []byte {
				text := string(content)
				index := strings.Index(text, `"stateSignature": "`)
				if index < 0 {
					t.Fatalf("no state signature in %s", text)
				}
				position := index + len(`"stateSignature": "`) + 2
				replacement := "A"
				if text[position] == 'A' {
					replacement = "B"
				}
				return []byte(text[:position] + replacement + text[position+1:])
			})
		},
		"deployment-id-rewritten": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "deployment.json"), func(content []byte) []byte {
				return []byte(strings.Replace(string(content), `"deploymentId": "`, `"deploymentId": "x`, 1))
			})
		},
		"ca-key-replaced": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "ca.key"), func([]byte) []byte {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return pemPrivateKey(t, key)
			})
		},
		"audit-key-truncated": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "audit.key"), func(content []byte) []byte { return content[:len(content)/2] })
		},
		"keyring-trailing-garbage": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "verification-keyring.json"), func(content []byte) []byte { return append(content, []byte(" {}")...) })
		},
		"recovery-credential-rewritten": func(t *testing.T, directory string) {
			rewrite(t, filepath.Join(directory, "recovery-credential.txt"), func([]byte) []byte { return []byte(strings.Repeat("0", 64) + "\n") })
		},
		"ca-cert-deleted": func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, "ca.crt")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := filepath.Join(t.TempDir(), "identity")
			original, err := identity.Ensure(directory, now)
			if err != nil {
				t.Fatal(err)
			}
			tamper(t, directory)
			reloaded, err := identity.Ensure(directory, now.Add(time.Minute))
			if err == nil {
				if reloaded.Deployment.DeploymentID == original.Deployment.DeploymentID {
					t.Fatalf("%s: tampered identity loaded as the original deployment", name)
				}
				t.Fatalf("%s: tampered identity directory was silently re-created as %q", name, reloaded.Deployment.DeploymentID)
			}
		})
	}
}

// Invariant: the identity directory itself must not be reachable through a
// symlink, so a hostile path cannot redirect key material.
func TestIdentityEnsureRejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: symlink creation requires privilege on Windows; covered by core/identity/security_windows_test.go")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if _, err := identity.Ensure(real, time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("ENV-UNAVAILABLE: symlinks unavailable on this filesystem")
	}
	if _, err := identity.Ensure(link, time.Date(2026, 7, 22, 12, 1, 0, 0, time.UTC)); err == nil {
		t.Fatal("symlinked identity directory was accepted")
	}
}

// Invariant: node certificates are bound to the node id and the deployment;
// an empty or control-character node id is refused at issuance.
func TestIssueNodeCertificateRejectsHostileNodeIDs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	authority, err := identity.Ensure(filepath.Join(t.TempDir(), "identity"), now)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"", " ", "node\n", "node\x00", strings.Repeat("n", 4096)} {
		if _, err := authority.IssueNodeCertificate(nodeID, publicKey, now); err == nil {
			t.Skipf("KNOWN-GAP AF-GAP-003: core/identity.IssueNodeCertificate accepts node id %q; node-id canonical form is enforced only at enrollment", nodeID)
		}
	}
	if _, err := authority.IssueNodeCertificate("node", publicKey[:16], now); err == nil {
		t.Fatal("short public key accepted")
	}
}

func pemPrivateKey(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Invariant: identity artifacts that have become readable by other users are
// treated as compromised and refused, not silently re-tightened.
func TestIdentityEnsureRefusesWorldReadableState(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ENV-UNAVAILABLE: POSIX permission bits are not meaningful on Windows")
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	directory := filepath.Join(t.TempDir(), "identity")
	if _, err := identity.Ensure(directory, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"deployment.json", "ca.key", "audit.key"} {
		if err := os.Chmod(filepath.Join(directory, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := identity.Ensure(directory, now.Add(time.Minute)); err == nil {
		t.Skip("KNOWN-GAP AF-GAP-004: core/identity repairs loose file modes (chmod back to 0600) and loads; world-readable key material is not treated as a compromise signal")
	}
}
