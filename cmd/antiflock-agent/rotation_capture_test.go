package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRotationCapturePrivatePublication(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rotation capture requires Linux")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "native.pb")
	if err := checkCaptureDestination(destination); err != nil {
		t.Fatal(err)
	}
	original := []byte{0x08, 0x01}
	if err := writePrivateCapture(destination, original); err != nil {
		t.Fatal(err)
	}
	if err := checkCaptureDestination(destination); err == nil {
		t.Fatal("accepted an existing capture destination")
	}
	if err := writePrivateCapture(destination, []byte{0x08, 0x02}); err == nil {
		t.Fatal("replaced an existing capture")
	}
	current, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("capture changed")
	}
	mode, err := os.Stat(destination)
	if err != nil || mode.Mode().Perm() != 0o600 {
		t.Fatal("capture must be private")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("capture staging left an extra file")
	}
}

func TestRotationIntentRefusesNonregularInputs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rotation capture requires Linux")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	intent := filepath.Join(directory, "intent.json")
	if err := os.WriteFile(intent, []byte("bounded owner receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := readRotationIntentFile(intent); err != nil || !bytes.Equal(result, []byte("bounded owner receipt")) {
		t.Fatal("bounded intent read failed")
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(intent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRotationIntentFile(link); err == nil {
		t.Fatal("accepted linked intent")
	}
}
