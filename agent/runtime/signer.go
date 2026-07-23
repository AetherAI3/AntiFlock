package runtime

import (
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/agent/collectors"
	"github.com/DBarr3/AntiFlock/core/events"
	"github.com/DBarr3/AntiFlock/internal/model"
)

type fileSigner struct {
	nodeID string
	privateKey ed25519.PrivateKey
	clock func() time.Time
}

// LoadFileSigner loads the Ed25519 seed created during enrollment. The seed
// file must be private and regular; it is never copied into the queue.
func LoadFileSigner(nodeID, path string, clock func() time.Time) (collectors.EventSigner, error) {
	if strings.TrimSpace(nodeID) == "" || strings.TrimSpace(path) == "" { return nil, errors.New("agent signer requires node id and key file") }
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 { return nil, errors.New("agent key file must be a private regular file") }
	seed, err := os.ReadFile(path); if err != nil || len(seed) != ed25519.SeedSize { return nil, errors.New("agent key file must contain one Ed25519 seed") }
	if clock == nil { clock = func() time.Time { return time.Now().UTC() } }
	return &fileSigner{nodeID: nodeID, privateKey: ed25519.NewKeyFromSeed(seed), clock: clock}, nil
}

func (signer *fileSigner) Sign(event *model.EventEnvelope) error {
	if signer == nil { return errors.New("agent signer is required") }
	return events.SignAt(event, signer.nodeID, signer.privateKey, signer.clock().UTC())
}
