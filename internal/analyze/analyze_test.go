package analyze

import (
	"fmt"
	"strings"
	"testing"

	"github.com/radnyxx/driftwatch/internal/artifact"
)

func bundle(manifest string, js map[string]string) *artifact.Bundle {
	files := map[string]string{"manifest.json": manifest}
	for k, v := range js {
		files[k] = v
	}
	return artifact.FromFiles("test", files)
}

func mf(version, extra string) string {
	return `{"manifest_version":3,"name":"T","version":"` + version + `"` + extra + `}`
}

func compare(t *testing.T, o, n *artifact.Bundle) *Result {
	t.Helper()
	r, err := Compare(o, n, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(r *Result, code string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Code == code {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestIdenticalReleasesAreQuiet(t *testing.T) {
	b := bundle(mf("1", `,"permissions":["storage"]`), map[string]string{"a.js": "var a=1;"})
	r := compare(t, b, b)
	if len(r.Findings) != 0 || r.Score != 0 || r.Verdict != "low" {
		t.Fatalf("expected quiet result, got %+v", r)
	}
}

func TestBroadHostAndPermissions(t *testing.T) {
	o := bundle(mf("1", `,"permissions":["storage"],"host_permissions":["https://a.com/*"]`), nil)
	n := bundle(mf("2", `,"permissions":["storage","cookies"],"host_permissions":["<all_urls>"]`), nil)
	r := compare(t, o, n)
	if f := find(r, "HOST_BROADENED"); f == nil || f.Points != 40 {
		t.Errorf("HOST_BROADENED missing or wrong: %+v", f)
	}
	if f := find(r, "PERM_ADDED"); f == nil || f.Points != 25 {
		t.Errorf("PERM_ADDED missing or wrong: %+v", f)
	}
	if find(r, "PERM_REMOVED") != nil {
		t.Error("nothing was removed")
	}
}

func TestBroadHostAlreadyPresentIsNotNew(t *testing.T) {
	o := bundle(mf("1", `,"host_permissions":["<all_urls>"]`), nil)
	n := bundle(mf("2", `,"host_permissions":["<all_urls>","*://*/*"]`), nil)
	if find(compare(t, o, n), "HOST_BROADENED") != nil {
		t.Error("equivalent breadth should not be reported again")
	}
}

func TestMV2MixedPermissionsSplit(t *testing.T) {
	o := bundle(`{"manifest_version":2,"name":"T","version":"1","permissions":["tabs"]}`, nil)
	n := bundle(`{"manifest_version":2,"name":"T","version":"2","permissions":["tabs","https://*.evil.test/*"]}`, nil)
	r := compare(t, o, n)
	if f := find(r, "HOST_ADDED"); f == nil || f.Points != 8 {
		t.Errorf("wildcard-subdomain host should score 8, got %+v", f)
	}
	if find(r, "PERM_ADDED") != nil {
		t.Error("host pattern must not be treated as an API permission")
	}
}

func TestOptionalPermissionsScoreHalf(t *testing.T) {
	o := bundle(mf("1", ``), nil)
	n := bundle(mf("2", `,"optional_permissions":["cookies"]`), nil)
	if f := find(compare(t, o, n), "PERM_ADDED"); f == nil || f.Points != 12 {
		t.Errorf("want 12, got %+v", f)
	}
}

func TestCSPWeakened(t *testing.T) {
	o := bundle(mf("1", `,"content_security_policy":{"extension_pages":"script-src 'self'"}`), nil)
	n := bundle(mf("2", `,"content_security_policy":{"extension_pages":"script-src 'self' 'unsafe-eval' https://x.test"}`), nil)
	f := find(compare(t, o, n), "CSP_WEAKENED")
	if f == nil || len(f.Items) != 2 {
		t.Fatalf("want 2 CSP risks, got %+v", f)
	}
}

func TestNewRemoteDomainsAndIgnore(t *testing.T) {
	o := bundle(mf("1", ``), map[string]string{"a.js": `fetch("https://api.good.test/x")`})
	n := bundle(mf("2", ``), map[string]string{"a.js": `fetch("https://api.good.test/x");fetch("https://new.bad.test/y");
		var w="http://www.w3.org/2000/svg"; var ip="http://203.0.113.9/p"; var l="http://localhost:3000/"`})
	r := compare(t, o, n)
	d := find(r, "NEW_REMOTE_DOMAIN")
	if d == nil || len(d.Items) != 1 || d.Items[0] != "new.bad.test" {
		t.Errorf("domains: %+v", d)
	}
	if ip := find(r, "NEW_REMOTE_IP"); ip == nil || ip.Items[0] != "203.0.113.9" {
		t.Errorf("ips: %+v", ip)
	}
	r2, _ := Compare(o, n, Options{IgnoreDomains: []string{"bad.test"}})
	if find(r2, "NEW_REMOTE_DOMAIN") != nil {
		t.Error("-ignore-domain should suppress subdomains")
	}
}

func TestObfuscationHeuristics(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString(fmt.Sprintf("var _0x%04x=1;\n", 0x1a00+i))
	}
	sb.WriteString(`eval(atob("Zm9v"));`)
	o := bundle(mf("1", ``), map[string]string{"a.js": "var a = 1;"})
	n := bundle(mf("2", ``), map[string]string{"a.js": "var a = 1;", "loader.js": sb.String()})
	r := compare(t, o, n)
	if f := find(r, "OBFUSCATION_SPIKE"); f == nil || f.Points != 25 {
		t.Errorf("OBFUSCATION_SPIKE: %+v", f)
	}
	if find(r, "DYNAMIC_CODE_INTRODUCED") == nil {
		t.Error("eval introduction should be reported")
	}
	// Plain minified code must not trip the heuristic.
	min := "function a(b){return b.map(function(c){return c*2})}" + strings.Repeat("var q=1;", 2000)
	if looksObfuscated([]byte(min), 0, 0) {
		t.Error("minified code is not obfuscation")
	}
}

func TestUpdateURLAndNameChange(t *testing.T) {
	o := bundle(mf("1", ``), nil)
	n := bundle(`{"manifest_version":2,"name":"Totally New Name","version":"2","update_url":"https://updates.evil.test/u.xml"}`, nil)
	r := compare(t, o, n)
	if f := find(r, "UPDATE_URL_CHANGED"); f == nil || f.Points != 35 {
		t.Errorf("UPDATE_URL_CHANGED: %+v", f)
	}
	if find(r, "NAME_CHANGED") == nil {
		t.Error("NAME_CHANGED expected")
	}
	store := bundle(`{"manifest_version":2,"name":"T","version":"2","update_url":"https://clients2.google.com/service/update2/crx"}`, nil)
	if find(compare(t, o, store), "UPDATE_URL_CHANGED") != nil {
		t.Error("Chrome Web Store update URL is normal")
	}
}

func TestScoreCapsAt100(t *testing.T) {
	o := bundle(mf("1", ``), nil)
	n := bundle(mf("2", `,"permissions":["debugger","proxy","cookies","webRequest","history"],"host_permissions":["<all_urls>"],
		"content_scripts":[{"matches":["<all_urls>"],"js":["c.js"],"world":"MAIN"}]`), map[string]string{"c.js": `eval("1")`})
	r := compare(t, o, n)
	if r.Score != 100 || r.Verdict != "critical" {
		t.Errorf("score=%d verdict=%s", r.Score, r.Verdict)
	}
}

func TestMissingManifest(t *testing.T) {
	if _, err := Analyze(artifact.FromFiles("x", map[string]string{"a.js": "1"}), Options{}); err == nil {
		t.Error("expected manifest error")
	}
}
