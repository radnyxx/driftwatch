// Package artifact loads a browser-extension release (CRX, XPI/ZIP or an
// unpacked directory) into memory so it can be analysed and diffed.
package artifact

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxFiles     = 20000
	maxAnalysed  = 20 << 20  // per script/manifest file
	maxTotalSize = 512 << 20 // whole package, guards against zip bombs
)

// Bundle is one loaded release.
type Bundle struct {
	Source string
	Hashes map[string]string // every file -> sha256
	Text   map[string][]byte // manifest, scripts and HTML (the files we analyse)
	total  int64
}

// New returns an empty bundle.
func New(source string) *Bundle {
	return &Bundle{Source: source, Hashes: map[string]string{}, Text: map[string][]byte{}}
}

// FromFiles builds a bundle from in-memory content (used by tests).
func FromFiles(source string, files map[string]string) *Bundle {
	b := New(source)
	for name, content := range files {
		_ = b.add(name, strings.NewReader(content))
	}
	return b
}

// Names returns all file names, sorted.
func (b *Bundle) Names() []string {
	out := make([]string, 0, len(b.Hashes))
	for n := range b.Hashes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func isAnalysed(name string) bool {
	l := strings.ToLower(name)
	if l == "manifest.json" {
		return true
	}
	for _, ext := range []string{".js", ".mjs", ".cjs", ".html", ".htm"} {
		if strings.HasSuffix(l, ext) {
			return true
		}
	}
	return false
}

func normalize(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	return path.Clean("/" + name)[1:]
}

func (b *Bundle) add(name string, r io.Reader) error {
	name = normalize(name)
	if name == "" {
		return nil
	}
	if len(b.Hashes) >= maxFiles {
		return errors.New("package has too many files")
	}
	h := sha256.New()
	if isAnalysed(name) {
		data, err := io.ReadAll(io.LimitReader(r, maxAnalysed))
		if err != nil {
			return err
		}
		h.Write(data)
		b.Text[name] = data
		b.total += int64(len(data))
	} else {
		n, err := io.Copy(h, io.LimitReader(r, maxTotalSize))
		if err != nil {
			return err
		}
		b.total += n
	}
	if b.total > maxTotalSize {
		return errors.New("package exceeds size limit (possible zip bomb)")
	}
	b.Hashes[name] = hex.EncodeToString(h.Sum(nil))
	return nil
}

// Load reads a .crx, .xpi, .zip file or an unpacked extension directory.
func Load(p string) (*Bundle, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	b := New(p)
	if st.IsDir() {
		return b, b.loadDir(p)
	}
	if st.Size() > maxTotalSize {
		return nil, fmt.Errorf("%s is larger than %d MB", p, maxTotalSize>>20)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	zipData, err := stripCRX(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if err := b.loadZip(zipData); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return b, nil
}

var errTruncated = errors.New("truncated CRX header")

// stripCRX removes the CRX2/CRX3 header, leaving the embedded ZIP.
// Data that does not start with the "Cr24" magic is returned unchanged.
func stripCRX(d []byte) ([]byte, error) {
	if len(d) < 12 || string(d[:4]) != "Cr24" {
		return d, nil
	}
	switch v := binary.LittleEndian.Uint32(d[4:8]); v {
	case 2:
		if len(d) < 16 {
			return nil, errTruncated
		}
		off := 16 + uint64(binary.LittleEndian.Uint32(d[8:12])) + uint64(binary.LittleEndian.Uint32(d[12:16]))
		if off > uint64(len(d)) {
			return nil, errTruncated
		}
		return d[off:], nil
	case 3:
		off := 12 + uint64(binary.LittleEndian.Uint32(d[8:12]))
		if off > uint64(len(d)) {
			return nil, errTruncated
		}
		return d[off:], nil
	default:
		return nil, fmt.Errorf("unsupported CRX version %d", v)
	}
}

func (b *Bundle) loadZip(data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("not a valid extension package: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = b.add(f.Name, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *Bundle) loadDir(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // skip symlinks, devices
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		return b.add(filepath.ToSlash(rel), f)
	})
}
