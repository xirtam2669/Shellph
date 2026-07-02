package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeLowercasesFlagValues(t *testing.T) {
	cfg := normalize(config{
		inputFmt:  "BIN",
		operation: "XOR",
		outputFmt: "ARRAY",
		language:  "GO",
	})

	if cfg.inputFmt != "bin" || cfg.operation != "xor" || cfg.outputFmt != "array" || cfg.language != "go" {
		t.Fatalf("normalize failed: %+v", cfg)
	}
}

func TestValidateAllowsDefaultKeyAndIV(t *testing.T) {
	cfg := config{
		file:      "input.bin",
		inputFmt:  "bin",
		operation: "aes",
		outputFmt: "bin",
		language:  "go",
		key:       "1234567890123456",
		iv:        "1234567890123456",
	}

	if err := validate(cfg); err != nil {
		t.Fatalf("validate should allow default key/iv: %v", err)
	}
}

func TestValidateAllowsDefaultKeyForXORAndRC4(t *testing.T) {
	for _, op := range []string{"xor", "rc4"} {
		t.Run(op, func(t *testing.T) {
			cfg := config{
				file:      "input.bin",
				inputFmt:  "bin",
				operation: op,
				outputFmt: "bin",
				language:  "go",
				key:       "1234567890123456",
			}

			if err := validate(cfg); err != nil {
				t.Fatalf("validate should allow default key for %s: %v", op, err)
			}
		})
	}
}

func TestRunIPv4GoStringShouldBeStringVariable(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.go")

	if err := os.WriteFile(infile, []byte{192, 168, 1, 10}, 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "ipv4",
		outputFmt: "string",
		language:  "go",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	gotBytes, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)
	if got != "var encrypted = \"192.168.1.10\\n\"\n" {
		t.Fatalf("expected Go string variable IPv4 output, got:\n%s", got)
	}
	if strings.Contains(got, "[]byte") || strings.Contains(got, "[]string") {
		t.Fatalf("IPv4 string output should not be an array:\n%s", got)
	}
}

func TestRunIPv4GoArrayShouldBeStringArray(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.go")

	if err := os.WriteFile(infile, []byte{192, 168, 1, 10}, 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "ipv4",
		outputFmt: "array",
		language:  "go",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	gotBytes, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)
	want := "var encrypted = []string{\n    \"192.168.1.10\",\n}\n"
	if got != want {
		t.Fatalf("expected Go []string IPv4 output\nwant:\n%s\ngot:\n%s", want, got)
	}
	if strings.Contains(got, "[]byte") {
		t.Fatalf("IPv4 array output should not be byte array:\n%s", got)
	}
}

func TestRunMACGoStringShouldBeStringVariable(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.go")

	if err := os.WriteFile(infile, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "mac",
		outputFmt: "string",
		language:  "go",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	gotBytes, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)
	if got != "var encrypted = \"aa:bb:cc:dd:ee:ff\\n\"\n" {
		t.Fatalf("expected Go string variable MAC output, got:\n%s", got)
	}
}

func TestRunUUIDGoArrayShouldBeStringArray(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.go")

	input := []byte{
		0x4d, 0x5a, 0x41, 0x52,
		0x55, 0x48,
		0x89, 0xe5,
		0x48, 0x83,
		0xec, 0x20, 0x48, 0x83, 0xe4, 0xf0,
	}

	if err := os.WriteFile(infile, input, 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "uuid",
		outputFmt: "array",
		language:  "go",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	gotBytes, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)
	want := "var encrypted = []string{\n    \"4d5a4152-5548-89e5-4883-ec204883e4f0\",\n}\n"
	if got != want {
		t.Fatalf("expected Go []string UUID output\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestRunXORGoArrayStillUsesByteArray(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.go")

	if err := os.WriteFile(infile, []byte{0x41, 0x42}, 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "xor",
		outputFmt: "array",
		language:  "go",
		key:       "\x01",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	gotBytes, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	got := string(gotBytes)
	if !strings.Contains(got, "var encrypted = []byte{") {
		t.Fatalf("XOR array output should still be byte array:\n%s", got)
	}
	if !strings.Contains(got, "0x40, 0x43") {
		t.Fatalf("unexpected XOR result:\n%s", got)
	}
}

func TestRunAESWithDefaultKeyAndIV(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "in.bin")
	outfile := filepath.Join(dir, "out.bin")

	if err := os.WriteFile(infile, []byte("ABC"), 0600); err != nil {
		t.Fatal(err)
	}

	err := run(config{
		file:      infile,
		inputFmt:  "bin",
		operation: "aes",
		outputFmt: "bin",
		language:  "go",
		key:       "1234567890123456",
		iv:        "1234567890123456",
		outfile:   outfile,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	got, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 16 {
		t.Fatalf("expected AES padded ciphertext length 16, got %d", len(got))
	}
}
