package enforcement

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestPlanVerificationFileLoadersRejectAmbiguousInput(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	directory := t.TempDir()
	planPath := filepath.Join(directory, "plan.json")
	manifestPath := filepath.Join(directory, "capabilities.json")
	keyPath := filepath.Join(directory, "policy.pem")
	planJSON, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(fixture.planPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		planPath:     planJSON,
		manifestPath: manifestJSON,
		keyPath:      pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadPlanJSON(planPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapabilityManifestJSON(manifestPath); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadPlanPublicKey(keyPath); err != nil || !key.Equal(fixture.planPublicKey) {
		t.Fatalf("load public key = %x, %v", key, err)
	}
	if err := os.WriteFile(planPath, append(planJSON[:len(planJSON)-1], []byte(`,"futureUnsafe":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlanJSON(planPath); err == nil {
		t.Fatal("plan loader accepted an unknown field")
	}
	if err := os.WriteFile(keyPath, append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), []byte("unexpected")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlanPublicKey(keyPath); err == nil {
		t.Fatal("public-key loader accepted trailing content")
	}
}

func TestPlanLoaderRejectsSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "plan.json")
	if err := os.WriteFile(target, []byte(`{"id":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadPlanJSON(link); err == nil {
		t.Fatal("plan loader accepted a symlink")
	}
}
