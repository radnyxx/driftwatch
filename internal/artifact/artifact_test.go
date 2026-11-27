package artifact

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func crx3(zipData []byte) []byte {
	header := []byte("fake-protobuf-header")
	out := []byte("Cr24")
	out = binary.LittleEndian.AppendUint32(out, 3)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(header)))
	out = append(out, header...)
	return append(out, zipData...)
}

func crx2(zipData []byte) []byte {
	pub, sig := []byte("PUBKEY"), []byte("SIGNATURE")
	out := []byte("Cr24")
	out = binary.LittleEndian.AppendUint32(out, 2)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(pub)))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(sig)))
	out = append(out, pub...)
	out = append(out, sig...)
	return append(out, zipData...)
}

func TestLoadFormats(t *testing.T) {
	files := map[string]string{"manifest.json": `{"name":"x","version":"1"}`, "a/b.js": "var x=1;", "icon.png": "PNG"}
	z := makeZip(t, files)
	dir := t.TempDir()
	cases := map[string][]byte{"plain.zip": z, "v3.crx": crx3(z), "v2.crx": crx2(z)}
	for name, data := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(b.Hashes) != 3 || len(b.Text) != 2 {
			t.Errorf("%s: hashes=%d text=%d, want 3 and 2", name, len(b.Hashes), len(b.Text))
		}
	}
}

func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "lib"), 0o755)
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{}`), 0o600)
	os.WriteFile(filepath.Join(dir, "lib", "x.js"), []byte("1"), 0o600)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Text["lib/x.js"]; !ok {
		t.Errorf("expected lib/x.js in %v", b.Names())
	}
}

func TestBadInputs(t *testing.T) {
	dir := t.TempDir()
	trunc := filepath.Join(dir, "trunc.crx")
	os.WriteFile(trunc, []byte("Cr24\x03\x00\x00\x00\xff\xff\xff\x7f"), 0o600)
	if _, err := Load(trunc); err == nil {
		t.Error("truncated CRX should fail")
	}
	junk := filepath.Join(dir, "junk.zip")
	os.WriteFile(junk, []byte("this is not a zip"), 0o600)
	if _, err := Load(junk); err == nil {
		t.Error("non-zip should fail")
	}
}

func TestNormalizeBlocksTraversal(t *testing.T) {
	for in, want := range map[string]string{"../../etc/passwd": "etc/passwd", "a\\b.js": "a/b.js", "./x.js": "x.js"} {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q)=%q want %q", in, got, want)
		}
	}
}
