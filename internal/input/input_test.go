package input

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.bin")
	want := []byte{0x00, 0x41, 0xff}

	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path, "bin")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("bin mismatch: want %x got %x", want, got)
	}
}

func TestLoadHexWithEscapesAndSpaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.hex")

	if err := os.WriteFile(path, []byte(`\x41 \x42 43`), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path, "hex")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	want := []byte{0x41, 0x42, 0x43}
	if !bytes.Equal(got, want) {
		t.Fatalf("hex mismatch: want %x got %x", want, got)
	}
}

func TestLoadEmptyFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")

	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path, "bin"); err == nil {
		t.Fatal("expected empty input file to fail")
	}
}

func TestLoadInvalidFormatFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.bin")

	if err := os.WriteFile(path, []byte{0x41}, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path, "bad"); err == nil {
		t.Fatal("expected invalid input format to fail")
	}
}
