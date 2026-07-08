package format

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderBin(t *testing.T) {
	in := []byte{0x41, 0x42}
	got, err := Render(in, "go", "bin")
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("bin output mismatch: want %x got %x", in, got)
	}
}

func TestRenderHex(t *testing.T) {
	got, err := Render([]byte{0x00, 0xab, 0xff}, "go", "hex")
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if string(got) != "00abff" {
		t.Fatalf("hex output mismatch: %q", got)
	}
}

func TestRenderArrayUsesByteArray(t *testing.T) {
	got, err := Render([]byte{0x41, 0x42}, "go", "array")
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	out := string(got)
	if !strings.Contains(out, "var encrypted = []byte{") || !strings.Contains(out, "0x41, 0x42") {
		t.Fatalf("expected Go byte array output, got:\n%s", out)
	}
}

func TestRenderStringUsesByteString(t *testing.T) {
	got, err := Render([]byte{0x41, 0x42}, "go", "string")
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	out := string(got)
	if out != "var encrypted = \"AB\"\n" {
		t.Fatalf("expected Go string variable, got:\n%s", out)
	}
}

func TestByteArrayForEachLanguage(t *testing.T) {
	cases := map[string]string{
		"c":          "unsigned char encrypted[] = {",
		"go":         "var encrypted = []byte{",
		"rust":       "let encrypted: [u8; 2] = [",
		"csharp":     "byte[] encrypted = new byte[] {",
		"powershell": "$encrypted = @(",
	}

	for lang, prefix := range cases {
		t.Run(lang, func(t *testing.T) {
			got, err := ByteArray([]byte{0x41, 0x42}, lang)
			if err != nil {
				t.Fatalf("ByteArray returned error: %v", err)
			}

			if !strings.Contains(got, prefix) || !strings.Contains(got, "0x41, 0x42") {
				t.Fatalf("unexpected %s byte array output:\n%s", lang, got)
			}
		})
	}
}

func TestByteStringForEachLanguage(t *testing.T) {
	cases := map[string]string{
		"c":          "unsigned char encrypted[] =\n    \"\\x41\\x42\";\n",
		"go":         "var encrypted = \"AB\"\n",
		"rust":       "let encrypted = \"AB\";\n",
		"csharp":     "string encrypted = \"AB\";\n",
		"powershell": "$encrypted = @\"\nAB\"@\n",
	}

	for lang, want := range cases {
		t.Run(lang, func(t *testing.T) {
			got, err := ByteString([]byte{0x41, 0x42}, lang)
			if err != nil {
				t.Fatalf("ByteString returned error: %v", err)
			}
			if got != want {
				t.Fatalf("ByteString mismatch\nwant: %q\n got: %q", want, got)
			}
		})
	}
}

func TestTextStringForEachLanguage(t *testing.T) {

	cases := map[string]string{
		"c": `char *encrypted[] = {
			"alpha",
			"beta",
		};` + "\n",

		"go":         `var encrypted = "alpha\nbeta\n"` + "\n",
		"rust":       `let encrypted = "alpha\nbeta\n";` + "\n",
		"csharp":     `string encrypted = "alpha\nbeta\n";` + "\n",
		"powershell": "$encrypted = @\"\nalpha\nbeta\n\"@\n",
	}

	for lang, want := range cases {
		t.Run(lang, func(t *testing.T) {
			got, err := TextString("alpha\nbeta\n", lang)
			if err != nil {
				t.Fatalf("TextString returned error: %v", err)
			}
			if got != want {
				t.Fatalf("TextString mismatch\nwant: %q\n got: %q", want, got)
			}
		})
	}
}

func TestStringArrayForEachLanguage(t *testing.T) {
	values := []string{"alpha", "beta"}

	cases := map[string][]string{
		"c":          {`char* encrypted[] = {`, `"alpha",`, `"beta",`, `};`},
		"go":         {`var encrypted = []string{`, `"alpha",`, `"beta",`, `}`},
		"rust":       {`let encrypted = [`, `"alpha",`, `"beta",`, `];`},
		"csharp":     {`string[] encrypted = new string[] {`, `"alpha",`, `"beta",`, `};`},
		"powershell": {`$encrypted = @(`, `"alpha",`, `"beta",`, `)`},
	}

	for lang, parts := range cases {
		t.Run(lang, func(t *testing.T) {
			got, err := StringArray(values, lang)
			if err != nil {
				t.Fatalf("StringArray returned error: %v", err)
			}

			for _, part := range parts {
				if !strings.Contains(got, part) {
					t.Fatalf("expected %q in %s output:\n%s", part, lang, got)
				}
			}
		})
	}
}

func TestInvalidOutputAndLanguageFails(t *testing.T) {
	if _, err := Render([]byte{0x01}, "go", "bad"); err == nil {
		t.Fatal("expected invalid output format to fail")
	}
	if _, err := ByteArray([]byte{0x01}, "badlang"); err == nil {
		t.Fatal("expected invalid ByteArray language to fail")
	}
	if _, err := ByteString([]byte{0x01}, "badlang"); err == nil {
		t.Fatal("expected invalid ByteString language to fail")
	}
	if _, err := TextString("x", "badlang"); err == nil {
		t.Fatal("expected invalid TextString language to fail")
	}
	if _, err := StringArray([]string{"x"}, "badlang"); err == nil {
		t.Fatal("expected invalid StringArray language to fail")
	}
}
