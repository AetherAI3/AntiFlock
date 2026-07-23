package nano

import (
	"context"
	"errors"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
)

// StorageCursorStore adapts Core's SQLite store to the watchdog runner. The
// runner can therefore survive restarts without admitting mutable programs or
// persisting raw findings.
type StorageCursorStore struct {
	database *storage.DB
	clock func() time.Time
}

func NewStorageCursorStore(database *storage.DB, clock func() time.Time) (*StorageCursorStore, error) {
	if database == nil { return nil, errors.New("nano cursor database is required") }
	if clock == nil { clock = func() time.Time { return time.Now().UTC() } }
	return &StorageCursorStore{database: database, clock: clock}, nil
}

func (store *StorageCursorStore) Load(ctx context.Context, programDigest, nodeID string) (Cursor, error) {
	if store == nil { return Cursor{}, errors.New("nano cursor store is required") }
	record, err := store.database.LoadNanoCursor(ctx, programDigest, nodeID)
	if err != nil { return Cursor{}, err }
	return Cursor{Initialized: record.Initialized, NextDueUnix: record.NextDueUnix}, nil
}

func (store *StorageCursorStore) CompareAndSwap(ctx context.Context, programDigest, nodeID string, previous, next Cursor) (bool, error) {
	if store == nil { return false, errors.New("nano cursor store is required") }
	return store.database.CompareAndSwapNanoCursor(ctx, programDigest, nodeID, storage.NanoCursorRecord{Initialized: previous.Initialized, NextDueUnix: previous.NextDueUnix}, storage.NanoCursorRecord{Initialized: next.Initialized, NextDueUnix: next.NextDueUnix}, store.clock().UTC())
}
