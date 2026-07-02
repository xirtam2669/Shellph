package transform

import (
	"fmt"
	"strings"

	outfmt "shellph/internal/format"
)

func IPv4(data []byte, language string, outputFormat string) string {
	return chunked(data, 4, language, outputFormat, func(chunk []byte) string {
		return fmt.Sprintf("%d.%d.%d.%d", chunk[0], chunk[1], chunk[2], chunk[3])
	})
}

func MAC(data []byte, language string, outputFormat string) string {
	return chunked(data, 6, language, outputFormat, func(chunk []byte) string {
		parts := make([]string, len(chunk))
		for i, b := range chunk {
			parts[i] = fmt.Sprintf("%02x", b)
		}
		return strings.Join(parts, ":")
	})
}

func UUID(data []byte, language string, outputFormat string) string {
	return chunked(data, 16, language, outputFormat, func(c []byte) string {
		return fmt.Sprintf(
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			c[0], c[1], c[2], c[3],
			c[4], c[5],
			c[6], c[7],
			c[8], c[9],
			c[10], c[11], c[12], c[13], c[14], c[15],
		)
	})
}

func chunked(data []byte, size int, language string, outputFormat string, renderString func([]byte) string) string {
	var items []string

	for i := 0; i+size <= len(data); i += size {
		items = append(items, renderString(data[i:i+size]))
	}

	switch outputFormat {
	case "string":
		out, _ := outfmt.TextString(strings.Join(items, "\n")+"\n", language)
		return out
	case "array":
		out, _ := outfmt.StringArray(items, language)
		return out
	default:
		return strings.Join(items, "\n") + "\n"
	}
}
