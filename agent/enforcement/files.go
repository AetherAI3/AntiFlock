package enforcement

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const maximumPlanJSONBytes = 1 << 20

func LoadPlanJSON(path string) (*antiflockv1.Plan, error) {
	content, err := readBoundedRegularFile(path, maximumPlanJSONBytes)
	if err != nil {
		return nil, errors.New("read bounded signed plan file")
	}
	plan := &antiflockv1.Plan{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, plan); err != nil {
		return nil, errors.New("decode signed plan JSON")
	}
	return plan, nil
}

func LoadCapabilityManifestJSON(path string) (*antiflockv1.CapabilityManifest, error) {
	content, err := readBoundedRegularFile(path, 256<<10)
	if err != nil {
		return nil, errors.New("read bounded capability manifest file")
	}
	manifest := &antiflockv1.CapabilityManifest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(content, manifest); err != nil {
		return nil, errors.New("decode capability manifest JSON")
	}
	return manifest, nil
}

// LoadPlanPublicKey accepts one PKIX Ed25519 PUBLIC KEY PEM block. Trailing
// non-whitespace content, additional blocks, symlinks, and oversized files are
// rejected so the pinned trust root is unambiguous.
func LoadPlanPublicKey(path string) (ed25519.PublicKey, error) {
	content, err := readBoundedRegularFile(path, 16<<10)
	if err != nil {
		return nil, errors.New("read bounded policy public key file")
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("policy public key must contain one PKIX PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse policy public key")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("policy public key must be Ed25519")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" || maximum <= 0 {
		return nil, errors.New("file path and size bound are required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("read complete regular file")
	}
	return content, nil
}
