// Package analyze extracts security-relevant facts from an extension release
// and compares two releases.
package analyze

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/radnyxx/driftwatch/internal/artifact"
)

// Options tunes the analysis.
type Options struct {
	// IgnoreDomains are hosts (and their subdomains) never reported as remote endpoints.
	IgnoreDomains []string
}

// ContentScript is the part of a content_scripts entry we care about.
type ContentScript struct {
	Matches []string `json:"matches"`
	World   string   `json:"world,omitempty"`
}

// CodeStats summarises the scripts in a release.
type CodeStats struct {
	JSFiles         int      `json:"js_files"`
	JSBytes         int      `json:"js_bytes"`
	Eval            int      `json:"eval"`
	NewFunction     int      `json:"new_function"`
	Atob            int      `json:"atob"`
	ImportScripts   int      `json:"import_scripts"`
	ScriptInject    int      `json:"script_inject"`
	Obfuscated      []string `json:"obfuscated_files"`
	ObfuscatedBytes int      `json:"obfuscated_bytes"`
}

// Facts is everything driftwatch records about one release.
type Facts struct {
	Source                string            `json:"source"`
	Name                  string            `json:"name"`
	Version               string            `json:"version"`
	ManifestVersion       int               `json:"manifest_version"`
	Permissions           []string          `json:"permissions"`
	OptionalPermissions   []string          `json:"optional_permissions"`
	Hosts                 []string          `json:"hosts"`
	OptionalHosts         []string          `json:"optional_hosts"`
	ContentScripts        []ContentScript   `json:"content_scripts"`
	CSP                   map[string]string `json:"csp"`
	ExternallyConnectable []string          `json:"externally_connectable"`
	UpdateURL             string            `json:"update_url,omitempty"`
	Domains               []string          `json:"remote_domains"`
	IPHosts               []string          `json:"remote_ips"`
	Code                  CodeStats         `json:"code"`
}

// Analyze reads the manifest and scripts of a bundle.
func Analyze(b *artifact.Bundle, opt Options) (*Facts, error) {
	raw, ok := b.Text["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("%s: manifest.json not found at package root", b.Source)
	}
	f, err := parseManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", b.Source, err)
	}
	f.Source = b.Source
	scanCode(b, opt, f)
	return f, nil
}

func parseManifest(data []byte) (*Facts, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var m struct {
		Name                    string `json:"name"`
		Version                 string `json:"version"`
		ManifestVersion         int    `json:"manifest_version"`
		Permissions             []any  `json:"permissions"`
		OptionalPermissions     []any  `json:"optional_permissions"`
		HostPermissions         []any  `json:"host_permissions"`
		OptionalHostPermissions []any  `json:"optional_host_permissions"`
		ContentScripts          []struct {
			Matches []string `json:"matches"`
			World   string   `json:"world"`
		} `json:"content_scripts"`
		CSP                   json.RawMessage `json:"content_security_policy"`
		ExternallyConnectable struct {
			Matches []string `json:"matches"`
		} `json:"externally_connectable"`
		UpdateURL string `json:"update_url"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest.json is not valid JSON (comments are not supported): %w", err)
	}
	if m.Name == "" && m.Version == "" {
		return nil, errors.New("manifest.json has no name or version")
	}
	f := &Facts{
		Name: m.Name, Version: m.Version, ManifestVersion: m.ManifestVersion,
		CSP:                   parseCSP(m.CSP),
		ExternallyConnectable: sorted(m.ExternallyConnectable.Matches),
		UpdateURL:             m.UpdateURL,
	}
	p1, h1 := splitPerms(m.Permissions)
	p2, h2 := splitPerms(m.HostPermissions)
	op1, oh1 := splitPerms(m.OptionalPermissions)
	op2, oh2 := splitPerms(m.OptionalHostPermissions)
	f.Permissions = sorted(append(p1, p2...))
	f.Hosts = sorted(append(h1, h2...))
	f.OptionalPermissions = sorted(append(op1, op2...))
	f.OptionalHosts = sorted(append(oh1, oh2...))
	for _, cs := range m.ContentScripts {
		f.ContentScripts = append(f.ContentScripts, ContentScript{Matches: sorted(cs.Matches), World: strings.ToUpper(cs.World)})
	}
	return f, nil
}

func isHostPattern(p string) bool {
	return p == "<all_urls>" || strings.Contains(p, "://") || strings.HasPrefix(p, "*")
}

// splitPerms separates API permissions from host patterns (MV2 mixes them).
func splitPerms(items []any) (perms, hosts []string) {
	for _, it := range items {
		switch v := it.(type) {
		case string:
			if isHostPattern(v) {
				hosts = append(hosts, v)
			} else {
				perms = append(perms, v)
			}
		case map[string]any: // legacy object permissions, e.g. {"fileSystem": [...]}
			for k := range v {
				perms = append(perms, k)
			}
		}
	}
	return
}

func parseCSP(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		out["legacy"] = s
		return out
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) == nil {
		return m
	}
	return out
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// ---- code scanning --------------------------------------------------------

var (
	urlRe           = regexp.MustCompile(`(?i)\b(?:https?|wss?)://([a-z0-9][a-z0-9.\-]*[a-z0-9])(?::\d{1,5})?`)
	tldRe           = regexp.MustCompile(`^[a-z]{2,}$`)
	evalRe          = regexp.MustCompile(`\beval\s*\(`)
	newFuncRe       = regexp.MustCompile(`\bnew\s+Function\s*\(`)
	atobRe          = regexp.MustCompile(`\batob\s*\(`)
	fromCharCodeRe  = regexp.MustCompile(`String\.fromCharCode\s*\(`)
	importScriptsRe = regexp.MustCompile(`\bimportScripts\s*\(`)
	scriptInjectRe  = regexp.MustCompile(`createElement\(\s*["']script["']\s*\)`)
	hexIdentRe      = regexp.MustCompile(`\b_0x[0-9a-fA-F]{3,}\b`)
	hexEscapeRe     = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	b64BlobRe       = regexp.MustCompile(`[A-Za-z0-9+/]{400,}={0,2}`)
)

// Hosts that appear in comments and licence headers all over the web.
var defaultIgnore = []string{
	"w3.org", "schema.org", "mozilla.org", "chromium.org",
	"example.com", "example.org", "example.net", "reactjs.org",
}

func hostIgnored(host string, extra []string) bool {
	for _, list := range [][]string{defaultIgnore, extra} {
		for _, d := range list {
			d = strings.ToLower(strings.TrimPrefix(d, "."))
			if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
				return true
			}
		}
	}
	return false
}

func scanCode(b *artifact.Bundle, opt Options, f *Facts) {
	domains := map[string]struct{}{}
	ips := map[string]struct{}{}

	names := make([]string, 0, len(b.Text))
	for n := range b.Text {
		if n != "manifest.json" {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		src := b.Text[name]
		for _, m := range urlRe.FindAllSubmatch(src, -1) {
			host := strings.ToLower(string(m[1]))
			if ip := net.ParseIP(host); ip != nil {
				if !ip.IsLoopback() && !ip.IsUnspecified() {
					ips[host] = struct{}{}
				}
				continue
			}
			i := strings.LastIndexByte(host, '.')
			if i < 0 || !tldRe.MatchString(host[i+1:]) || hostIgnored(host, opt.IgnoreDomains) {
				continue
			}
			domains[host] = struct{}{}
		}

		l := strings.ToLower(name)
		if !(strings.HasSuffix(l, ".js") || strings.HasSuffix(l, ".mjs") || strings.HasSuffix(l, ".cjs")) {
			continue
		}
		cs := &f.Code
		cs.JSFiles++
		cs.JSBytes += len(src)
		ev, nf, ab := count(evalRe, src), count(newFuncRe, src), count(atobRe, src)
		cs.Eval += ev
		cs.NewFunction += nf
		cs.Atob += ab
		cs.ImportScripts += count(importScriptsRe, src)
		cs.ScriptInject += count(scriptInjectRe, src)
		if looksObfuscated(src, ev+nf, ab) {
			cs.Obfuscated = append(cs.Obfuscated, name)
			cs.ObfuscatedBytes += len(src)
		}
	}
	f.Domains = keys(domains)
	f.IPHosts = keys(ips)
}

func count(re *regexp.Regexp, src []byte) int { return len(re.FindAllIndex(src, -1)) }

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// looksObfuscated is a heuristic, not a verdict. Minified code alone does not
// trigger it; we need at least two independent signals (or a flood of _0x names,
// the signature of common JS obfuscators).
func looksObfuscated(src []byte, dynExec, atob int) bool {
	hexIdents := count(hexIdentRe, src)
	if hexIdents >= 100 {
		return true
	}
	signals := 0
	if hexIdents >= 20 {
		signals++
	}
	if count(hexEscapeRe, src) >= 100 {
		signals++
	}
	if dynExec > 0 && (atob > 0 || fromCharCodeRe.Match(src)) {
		signals++
	}
	if dynExec > 0 && b64BlobRe.Match(src) { // big encoded blob next to an exec primitive
		signals++
	}
	return signals >= 2
}
