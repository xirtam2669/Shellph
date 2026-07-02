package transform

import "testing"

func TestIPv4GoStringIsStringVariableAndDropsRemainder(t *testing.T) {
	data := []byte{192, 168, 1, 10, 99}
	want := "var encrypted = \"192.168.1.10\\n\"\n"
	got := IPv4(data, "go", "string")
	if got != want {
		t.Fatalf("IPv4 go string mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestIPv4GoArrayIsStringArrayAndDropsRemainder(t *testing.T) {
	data := []byte{192, 168, 1, 10, 99}
	want := "var encrypted = []string{\n    \"192.168.1.10\",\n}\n"
	got := IPv4(data, "go", "array")
	if got != want {
		t.Fatalf("IPv4 go array mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestMACGoStringIsStringVariableAndDropsRemainder(t *testing.T) {
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99}
	want := "var encrypted = \"aa:bb:cc:dd:ee:ff\\n\"\n"
	got := MAC(data, "go", "string")
	if got != want {
		t.Fatalf("MAC go string mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestMACGoArrayIsStringArrayAndDropsRemainder(t *testing.T) {
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99}
	want := "var encrypted = []string{\n    \"aa:bb:cc:dd:ee:ff\",\n}\n"
	got := MAC(data, "go", "array")
	if got != want {
		t.Fatalf("MAC go array mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestUUIDGoStringIsStringVariableAndDropsRemainder(t *testing.T) {
	data := []byte{
		0x4d, 0x5a, 0x41, 0x52,
		0x55, 0x48,
		0x89, 0xe5,
		0x48, 0x83,
		0xec, 0x20, 0x48, 0x83, 0xe4, 0xf0,
		0x99,
	}
	want := "var encrypted = \"4d5a4152-5548-89e5-4883-ec204883e4f0\\n\"\n"
	got := UUID(data, "go", "string")
	if got != want {
		t.Fatalf("UUID go string mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestUUIDGoArrayIsStringArrayAndDropsRemainder(t *testing.T) {
	data := []byte{
		0x4d, 0x5a, 0x41, 0x52,
		0x55, 0x48,
		0x89, 0xe5,
		0x48, 0x83,
		0xec, 0x20, 0x48, 0x83, 0xe4, 0xf0,
		0x99,
	}
	want := "var encrypted = []string{\n    \"4d5a4152-5548-89e5-4883-ec204883e4f0\",\n}\n"
	got := UUID(data, "go", "array")
	if got != want {
		t.Fatalf("UUID go array mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestPowerShellStringAndArraySemantics(t *testing.T) {
	data := []byte{192, 168, 1, 10}

	wantString := "$encrypted = @\"\n192.168.1.10\n\"@\n"
	if got := IPv4(data, "powershell", "string"); got != wantString {
		t.Fatalf("PowerShell string mismatch\nwant: %q\n got: %q", wantString, got)
	}

	wantArray := "$encrypted = @(\n    \"192.168.1.10\",\n)\n"
	if got := IPv4(data, "powershell", "array"); got != wantArray {
		t.Fatalf("PowerShell array mismatch\nwant: %q\n got: %q", wantArray, got)
	}
}
