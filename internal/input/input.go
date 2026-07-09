package input

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func Load(path string, inputFormat string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("input file is empty")
	}

	switch inputFormat {
	case "raw":
		return raw, nil
	case "hex":
		cleaned := cleanHex(string(raw))
		data, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid hex input: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("input file is empty after hex decoding")
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported input format %q", inputFormat)
	}
}

func cleanHex(s string) string {
	s = strings.ReplaceAll(s, "\\x", "")
	s = strings.ReplaceAll(s, "0x", "")
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == ',' || r == ';' || r == '{' || r == '}' || r == '[' || r == ']' || r == '"' || r == '\'' {
			return -1
		}
		return r
	}, s)
}
