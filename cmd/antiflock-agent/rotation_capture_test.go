//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRotationCapturePrivatePublication(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "native.pb")
	opened, err := openCaptureDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	original := []byte{0x08, 0x01}
	if err := writePrivateCapture(opened, filepath.Base(destination), original); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := openCaptureDestination(destination); err == nil {
		duplicate.Close()
		t.Fatal("accepted an existing capture destination")
	}
	if err := writePrivateCapture(opened, filepath.Base(destination), []byte{0x08, 0x02}); err == nil {
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
	pipe := filepath.Join(directory, "intent.pipe")
	if err := unix.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRotationIntentFile(pipe); err == nil {
		t.Fatal("accepted a nonregular intent")
	}
}

func TestRotationCaptureRefusesReplacedDirectory(t *testing.T) {
	parent := t.TempDir()
	requested := filepath.Join(parent, "capture")
	if err := os.Mkdir(requested, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(requested, "native.pb")
	opened, err := openCaptureDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	moved := filepath.Join(parent, "previous")
	if err := os.Rename(requested, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(requested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateCapture(opened, filepath.Base(destination), []byte{0x08, 0x01}); err == nil {
		t.Fatal("accepted a replaced capture directory")
	}
	for _, path := range []string{requested, moved} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unexpected capture or staging file: %v", err)
		}
	}
}

func TestRotationCaptureRefusesLinkedOrPublicDirectory(t *testing.T) {
	parent := t.TempDir()
	private := filepath.Join(parent, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if opened, err := openCaptureDestination(filepath.Join(link, "private", "native.pb")); err == nil {
		opened.Close()
		t.Fatal("accepted a linked directory ancestor")
	}
	if err := os.Chmod(private, 0o755); err != nil {
		t.Fatal(err)
	}
	if opened, err := openCaptureDestination(filepath.Join(private, "native.pb")); err == nil {
		opened.Close()
		t.Fatal("accepted a public capture parent")
	}
}
