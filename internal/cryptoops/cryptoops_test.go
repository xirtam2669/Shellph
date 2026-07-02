package cryptoops

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestXORRepeatingKey(t *testing.T) {
	got, err := XOR([]byte{0x01, 0x02}, []byte{0x41, 0x42, 0x43})
	if err != nil {
		t.Fatalf("XOR returned error: %v", err)
	}

	want := []byte{0x40, 0x40, 0x42}
	if !bytes.Equal(got, want) {
		t.Fatalf("XOR mismatch: want %x got %x", want, got)
	}
}

func TestXOREmptyKeyFails(t *testing.T) {
	if _, err := XOR(nil, []byte{0x41}); err == nil {
		t.Fatal("expected empty XOR key to fail")
	}
}

func TestRC4KnownVector(t *testing.T) {
	got, err := RC4([]byte("Key"), []byte("Plaintext"))
	if err != nil {
		t.Fatalf("RC4 returned error: %v", err)
	}

	want, _ := hex.DecodeString("bbf316e8d940af0ad3")
	if !bytes.Equal(got, want) {
		t.Fatalf("RC4 mismatch: want %x got %x", want, got)
	}
}

func TestRC4EmptyKeyFails(t *testing.T) {
	if _, err := RC4(nil, []byte{0x41}); err == nil {
		t.Fatal("expected empty RC4 key to fail")
	}
}

func TestAESCBCEncryptPadsAndEncrypts(t *testing.T) {
	got, err := AESCBCEncrypt(
		[]byte("1234567890123456"),
		[]byte("1234567890123456"),
		[]byte("ABC"),
	)
	if err != nil {
		t.Fatalf("AESCBCEncrypt returned error: %v", err)
	}

	if len(got) != 16 {
		t.Fatalf("expected one AES block after padding, got %d bytes", len(got))
	}

	if bytes.Equal(got, []byte("ABC")) {
		t.Fatal("ciphertext should not equal plaintext")
	}
}

func TestAESCBCInvalidKeyOrIVFails(t *testing.T) {
	if _, err := AESCBCEncrypt([]byte("short"), []byte("1234567890123456"), []byte("ABC")); err == nil {
		t.Fatal("expected invalid AES key length to fail")
	}

	if _, err := AESCBCEncrypt([]byte("1234567890123456"), []byte("short"), []byte("ABC")); err == nil {
		t.Fatal("expected invalid AES IV length to fail")
	}
}
