package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"shellph/internal/cryptoops"
	"shellph/internal/format"
	"shellph/internal/input"
	"shellph/internal/transform"
)

type config struct {
	file      string
	inputFmt  string
	operation string
	outputFmt string
	language  string
	key       string
	iv        string
	outfile   string
}

const (
	DefaultKey       = "1234567890123456"
	DefaultIV        = "1234567890123456"
	DefaultOut       = "out.bin"
	DefaultIn        = "in.bin"
	DefaultInputFmt  = "bin"
	DefaultOutputFmt = "bin"
)

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Shellph - Shellcode encryption and transformation toolkit\n\n")

		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  shellph [options]\n\n")

		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  shellph -f shellcode.bin -fmt bin -op aes -of array -ofl c\n")
		fmt.Fprintf(os.Stderr, "  shellph -f shellcode.bin -fmt bin -op uuid -of string -ofl powershell\n\n")

		fmt.Fprintf(os.Stderr, "Options:\n\n")

		fmt.Fprintf(os.Stderr, "  -f,   --file <file>                 Input file\n")
		fmt.Fprintf(os.Stderr, "  -fmt, --input-format <bin|hex>      Input format\n")
		fmt.Fprintf(os.Stderr, "  -op,  --operation <operation>       aes | rc4 | xor | ipv4 | mac | uuid\n")
		fmt.Fprintf(os.Stderr, "  -of,  --output-format <format>      bin | hex | string | array\n")
		fmt.Fprintf(os.Stderr, "  -ofl, --output-format-language      c | go | rust | csharp | powershell\n")
		fmt.Fprintf(os.Stderr, "  -k,   --key <key>                   Encryption key (default: 1234567890123456)\n")
		fmt.Fprintf(os.Stderr, "  -iv,  --iv <iv>                     AES IV (default: 1234567890123456)\n")
		fmt.Fprintf(os.Stderr, "  -o,   --outfile <file>              Output file (default: out.bin)\n")

		fmt.Fprintf(os.Stderr, "\n")
	}
	flag.StringVar(&cfg.file, "file", DefaultIn, "Input file path")
	flag.StringVar(&cfg.file, "f", DefaultIn, "Input file path")
	flag.StringVar(&cfg.inputFmt, "input-format", DefaultInputFmt, "Input format: hex or bin")
	flag.StringVar(&cfg.inputFmt, "fmt", DefaultInputFmt, "Input format: hex or bin")
	flag.StringVar(&cfg.operation, "operation", "", "Operation: rc4, aes, xor, ipv4, mac, uuid")
	flag.StringVar(&cfg.operation, "op", "", "Operation: rc4, aes, xor, ipv4, mac, uuid")
	flag.StringVar(&cfg.outputFmt, "output-format", DefaultOutputFmt, "Output format: bin, hex, string, array")
	flag.StringVar(&cfg.outputFmt, "of", DefaultOutputFmt, "Output format: bin, hex, string, array")
	flag.StringVar(&cfg.language, "output-format-language", "", "Language: c, go, rust, csharp, powershell")
	flag.StringVar(&cfg.language, "ofl", "", "Language: c, go, rust, csharp, powershell")
	flag.StringVar(&cfg.key, "key", DefaultKey, "Key for rc4, aes, xor")
	flag.StringVar(&cfg.key, "k", DefaultKey, "Key for rc4, aes, xor")
	flag.StringVar(&cfg.iv, "iv", DefaultIV, "AES IV, exactly 16 bytes")
	flag.StringVar(&cfg.outfile, "outfile", DefaultOut, "Output file path")
	flag.StringVar(&cfg.outfile, "o", DefaultOut, "Output file path")

	flag.Parse()

	// No flags were supplied.
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(0)
	}

	return normalize(cfg)
}

func normalize(cfg config) config {
	cfg.inputFmt = strings.ToLower(cfg.inputFmt)
	cfg.operation = strings.ToLower(cfg.operation)
	cfg.outputFmt = strings.ToLower(cfg.outputFmt)
	cfg.language = strings.ToLower(cfg.language)
	return cfg
}

func run(cfg config) error {
	if err := validate(cfg); err != nil {
		return err
	}

	fmt.Println("[+] Loading input from disk...")
	data, err := input.Load(cfg.file, cfg.inputFmt)
	if err != nil {
		return fmt.Errorf("failed during input file loading: %w", err)
	}

	result, err := applyOperation(cfg, data)
	if err != nil {
		return err
	}

	var out []byte
	if oneOf(cfg.operation, "ipv4", "mac", "uuid") {
		out = result
	} else {
		out, err = format.Render(result, cfg.language, cfg.outputFmt)
		if err != nil {
			return err
		}
	}

	if err := os.WriteFile(cfg.outfile, out, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("[+] Output written to %s\n", cfg.outfile)
	return nil
}

func validate(cfg config) error {
	if cfg.file == "" {
		return fmt.Errorf("missing required -f/--file")
	}
	if !oneOf(cfg.inputFmt, "hex", "bin") {
		return fmt.Errorf("invalid input format %q; use hex or bin", cfg.inputFmt)
	}
	if !oneOf(cfg.operation, "rc4", "aes", "xor", "ipv4", "mac", "uuid") {
		return fmt.Errorf("invalid operation %q", cfg.operation)
	}
	if !oneOf(cfg.outputFmt, "bin", "hex", "string", "array") {
		return fmt.Errorf("invalid output format %q", cfg.outputFmt)
	}
	if !oneOf(cfg.language, "c", "go", "rust", "csharp", "powershell") {
		return fmt.Errorf("invalid output language %q", cfg.language)
	}
	if oneOf(cfg.operation, "rc4", "aes", "xor") && cfg.key == "" {
		return fmt.Errorf("-k/--key is required for %s", cfg.operation)
	}
	if cfg.operation == "aes" && cfg.iv == "" {
		return fmt.Errorf("-iv/--iv is required for aes")
	}
	if cfg.outputFmt == "bin" && oneOf(cfg.operation, "ipv4", "mac", "uuid") {
		return fmt.Errorf("%s transform requires text output: use -of string or -of array", cfg.operation)
	}
	return nil
}

func applyOperation(cfg config, data []byte) ([]byte, error) {
	switch cfg.operation {
	case "rc4":
		return cryptoops.RC4([]byte(cfg.key), data)
	case "aes":
		return cryptoops.AESCBCEncrypt([]byte(cfg.key), []byte(cfg.iv), data)
	case "xor":
		return cryptoops.XOR([]byte(cfg.key), data)
	case "ipv4":
		return []byte(transform.IPv4(data, cfg.language, cfg.outputFmt)), nil
	case "mac":
		return []byte(transform.MAC(data, cfg.language, cfg.outputFmt)), nil
	case "uuid":
		return []byte(transform.UUID(data, cfg.language, cfg.outputFmt)), nil
	default:
		return nil, fmt.Errorf("unsupported operation %q", cfg.operation)
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
