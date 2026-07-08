package format

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func Render(data []byte, language string, outputFormat string) ([]byte, error) {
	switch outputFormat {
	case "bin":
		return data, nil
	case "hex":
		return []byte(hex.EncodeToString(data)), nil
	case "array":
		out, err := ByteArray(data, language)
		return []byte(out), err
	case "string":
		out, err := ByteString(data, language)
		return []byte(out), err
	default:
		return nil, fmt.Errorf("unsupported output format %q", outputFormat)
	}
}

func ByteArray(data []byte, language string) (string, error) {
	body := hexByteLines(data)

	switch language {
	case "c":
		return "unsigned char encrypted[] = {\n" + body + "\n};\n", nil
	case "go":
		return "var encrypted = []byte{\n" + body + "\n}\n", nil
	case "rust":
		return fmt.Sprintf("let encrypted: [u8; %d] = [\n%s\n];\n", len(data), body), nil
	case "csharp":
		return "byte[] encrypted = new byte[] {\n" + body + "\n};\n", nil
	case "powershell":
		return "$encrypted = @(\n" + body + "\n)\n", nil
	default:
		return "", fmt.Errorf("unsupported language %q", language)
	}
}

func ByteString(data []byte, language string) (string, error) {
	switch language {
	case "c":
		var b strings.Builder
		b.WriteString("unsigned char encrypted[] =\n    \"")
		for i, v := range data {
			if i > 0 && i%16 == 0 {
				b.WriteString("\"\n    \"")
			}
			b.WriteString(fmt.Sprintf("\\x%02x", v))
		}
		b.WriteString("\";\n")
		return b.String(), nil
	case "go":
		return fmt.Sprintf("var encrypted = %s\n", strconv.Quote(string(data))), nil
	case "rust":
		return fmt.Sprintf("let encrypted = %s;\n", strconv.Quote(string(data))), nil
	case "csharp":
		return fmt.Sprintf("string encrypted = %s;\n", strconv.Quote(string(data))), nil
	case "powershell":
		return fmt.Sprintf("$encrypted = @\"\n%s\"@\n", string(data)), nil
	default:
		return "", fmt.Errorf("unsupported language %q", language)
	}
}

func TextString(text string, language string) (string, error) {
	switch language {
	case "c":
		lines := strings.Split(strings.TrimSpace(text), "\n")

		var b strings.Builder
		b.WriteString("char *encrypted[] = {\n")

		for _, line := range lines {
			b.WriteString(fmt.Sprintf("    %s,\n", strconv.Quote(strings.TrimSpace(line))))
		}
		b.WriteString("};\n")

		return b.String(), nil
	case "go":
		return fmt.Sprintf("var encrypted = %s\n", strconv.Quote(text)), nil
	case "rust":
		return fmt.Sprintf("let encrypted = %s;\n", strconv.Quote(text)), nil
	case "csharp":
		return fmt.Sprintf("string encrypted = %s;\n", strconv.Quote(text)), nil
	case "powershell":
		return fmt.Sprintf("$encrypted = @\"\n%s\"@\n", text), nil
	default:
		return "", fmt.Errorf("unsupported language %q", language)
	}
}

func StringArray(values []string, language string) (string, error) {
	switch language {
	case "c":
		return quotedArray("char* encrypted[] = {\n", "};\n", values), nil
	case "go":
		return quotedArray("var encrypted = []string{\n", "}\n", values), nil
	case "rust":
		return quotedArray("let encrypted = [\n", "];\n", values), nil
	case "csharp":
		return quotedArray("string[] encrypted = new string[] {\n", "};\n", values), nil
	case "powershell":
		return quotedArray("$encrypted = @(\n", ")\n", values), nil
	default:
		return "", fmt.Errorf("unsupported language %q", language)
	}
}

func quotedArray(prefix, suffix string, values []string) string {
	var b strings.Builder
	b.WriteString(prefix)

	for _, value := range values {
		b.WriteString("    ")
		b.WriteString(strconv.Quote(value))
		b.WriteString(",\n")
	}

	b.WriteString(suffix)
	return b.String()
}

func hexByteLines(data []byte) string {
	var b strings.Builder
	b.WriteString("    ")

	for i, v := range data {
		if i > 0 && i%16 == 0 {
			b.WriteString("\n    ")
		}

		b.WriteString(fmt.Sprintf("0x%02x", v))

		if i != len(data)-1 {
			b.WriteString(", ")
		}
	}

	return b.String()
}
