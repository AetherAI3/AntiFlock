package runtime

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
)

type fileSigner struct {
	nodeID     string
	privateKey ed25519.PrivateKey
	clock      func() time.Time
}

// LoadFileSigner loads the Ed25519 seed created during enrollment. The seed
// file must be private and regular; it is never copied into the queue.
func LoadFileSigner(nodeID, path string, clock func() time.Time) (collectors.EventSigner, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, errors.New("agent signer requires node id")
	}
	privateKey, err := loadNodePrivateKey(path)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &fileSigner{nodeID: nodeID, privateKey: privateKey, clock: clock}, nil
}

// LoadNodeCertificate binds the approved mTLS certificate to the same Ed25519
// seed used for source-event signing. It avoids a second private-key copy.
func LoadNodeCertificate(certificatePath, seedPath string) (tls.Certificate, error) {
	privateKey, err := loadNodePrivateKey(seedPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	info, err := os.Lstat(certificatePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 1<<20 {
		return tls.Certificate{}, errors.New("node certificate file must be a bounded regular file")
	}
	content, err := os.ReadFile(certificatePath)
	if err != nil {
		return tls.Certificate{}, errors.New("read node certificate file")
	}
	values := make([][]byte, 0, 1)
	for rest := content; len(rest) != 0; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) == "" {
				break
			}
			return tls.Certificate{}, errors.New("node certificate file contains invalid PEM")
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return tls.Certificate{}, errors.New("node certificate is invalid")
			}
			values = append(values, block.Bytes)
		}
		rest = remaining
	}
	if len(values) == 0 {
		return tls.Certificate{}, errors.New("node certificate file contains no certificate")
	}
	leaf, err := x509.ParseCertificate(values[0])
	if err != nil {
		return tls.Certificate{}, errors.New("node certificate is invalid")
	}
	certificateKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !certificateKey.Equal(privateKey.Public()) {
		return tls.Certificate{}, errors.New("node certificate does not match enrolled seed")
	}
	return tls.Certificate{Certificate: values, PrivateKey: privateKey, Leaf: leaf}, nil
}

func loadNodePrivateKey(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("agent key file is required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("agent key file must be a private regular file")
	}
	seed, err := os.ReadFile(path)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("agent key file must contain one Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (signer *fileSigner) Sign(event *model.EventEnvelope) error {
	if signer == nil {
		return errors.New("agent signer is required")
	}
	return events.SignAt(event, signer.nodeID, signer.privateKey, signer.clock().UTC())
}
