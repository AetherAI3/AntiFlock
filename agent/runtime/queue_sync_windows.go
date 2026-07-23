//go:build windows

package runtime

// The production collector currently refuses non-Linux operation. Keep queue
// tests and library builds portable; Windows' atomic replacement durability is
// handled by its filesystem API and has no directory-fsync equivalent exposed
// by the Go standard library.
func syncQueueDirectory(string) error { return nil }
