package analyze

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/radnyxx/driftwatch/internal/artifact"
)

// Severity of a single finding, derived from its points.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

func severityFor(points int) Severity {
	switch {
	case points >= 30:
		return Critical
	case points >= 20:
		return High
	case points >= 8:
		return Medium
	case points > 0:
		return Low
	}
	return Info
}

// Finding is one risky (or notable) change between two releases.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Points   int      `json:"points"`
	Message  string   `json:"message"`
	Items    []string `json:"items,omitempty"`
}

// FileChanges counts package-level file differences.
type FileChanges struct {
	Added           int      `json:"added"`
	Removed         int      `json:"removed"`
	Modified        int      `json:"modified"`
	ModifiedScripts []string `json:"modified_scripts,omitempty"`
}

// Result is the outcome of comparing two releases.
type Result struct {
	Old      *Facts      `json:"old"`
	New      *Facts      `json:"new"`
	Findings []Finding   `json:"findings"`
	Files    FileChanges `json:"files"`
	Score    int         `json:"score"`
	Verdict  string      `json:"verdict"`
}

// Compare analyses both bundles and scores the change from old to new.
func Compare(oldB, newB *artifact.Bundle, opt Options) (*Result, error) {
	of, err := Analyze(oldB, opt)
	if err != nil {
		return nil, err
	}
	nf, err := Analyze(newB, opt)
	if err != nil {
		return nil, err
	}
	return CompareFacts(of, nf, diffFiles(oldB, newB)), nil
}

// CompareFacts scores the change between two already-analysed releases.
func CompareFacts(of, nf *Facts, files FileChanges) *Result {
	r := &Result{Old: of, New: nf, Files: files}
	r.Findings = diffFacts(of, nf)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Points != r.Findings[j].Points {
			return r.Findings[i].Points > r.Findings[j].Points
		}
		return r.Findings[i].Code < r.Findings[j].Code
	})
	for _, f := range r.Findings {
		r.Score += f.Points
	}
	if r.Score > 100 {
		r.Score = 100
	}
	r.Verdict = verdictFor(r.Score)
	return r
}

func verdictFor(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 15:
		return "medium"
	}
	return "low"
}

func diffFiles(a, b *artifact.Bundle) FileChanges {
	var fc FileChanges
	for name, hb := range b.Hashes {
		ha, ok := a.Hashes[name]
		switch {
		case !ok:
			fc.Added++
		case ha != hb:
			fc.Modified++
			if _, isText := b.Text[name]; isText && strings.HasSuffix(strings.ToLower(name), "js") {
				fc.ModifiedScripts = append(fc.ModifiedScripts, name)
			}
		}
	}
	for name := range a.Hashes {
		if _, ok := b.Hashes[name]; !ok {
			fc.Removed++
		}
	}
	sort.Strings(fc.ModifiedScripts)
	return fc
}

// ---- rules ----------------------------------------------------------------

type collector struct{ out []Finding }

func (c *collector) add(code string, points int, msg string, items ...string) {
	c.out = append(c.out, Finding{Code: code, Severity: severityFor(points), Points: points, Message: msg, Items: items})
}

func diffFacts(o, n *Facts) []Finding {
	c := &collector{}

	if o.Name != n.Name && !strings.HasPrefix(o.Name, "__MSG_") && !strings.HasPrefix(n.Name, "__MSG_") {
		c.add("NAME_CHANGED", 10, "Extension name changed (a common sign of a transferred or hijacked listing)",
			fmt.Sprintf("%q -> %q", o.Name, n.Name))
	}

	permFindings(c, o.Permissions, n.Permissions, false)
	permFindings(c, o.OptionalPermissions, n.OptionalPermissions, true)
	hostFindings(c, o.Hosts, n.Hosts, false)
	hostFindings(c, o.OptionalHosts, n.OptionalHosts, true)
	contentScriptFindings(c, o, n)
	cspFindings(c, o, n)

	if added := newItems(o.ExternallyConnectable, n.ExternallyConnectable); len(added) > 0 {
		c.add("EXTERNALLY_CONNECTABLE_ADDED", 10, "Websites can now message the extension", added...)
	}

	if n.UpdateURL != "" && n.UpdateURL != o.UpdateURL && !knownStoreUpdate(n.UpdateURL) {
		c.add("UPDATE_URL_CHANGED", 35, "Self-hosted update URL set or changed (bypasses store review)", n.UpdateURL)
	}

	codeFindings(c, o, n)
	return c.out
}

// permWeights: how much a newly granted API permission adds to the risk score.
var permWeights = map[string]int{
	"debugger": 35, "proxy": 30, "desktopCapture": 25, "nativeMessaging": 25,
	"cookies": 25, "webRequestBlocking": 20, "webRequest": 20, "history": 20,
	"management": 20, "clipboardRead": 20, "scripting": 15, "downloads": 15,
	"browsingData": 15, "privacy": 15, "contentSettings": 15, "tabCapture": 15,
	"pageCapture": 15, "tabs": 10, "webNavigation": 10, "identity": 10,
	"geolocation": 10, "declarativeNetRequest": 10, "topSites": 8, "bookmarks": 8,
	"offscreen": 8, "background": 5, "declarativeNetRequestFeedback": 5,
	"clipboardWrite": 5, "activeTab": 3, "notifications": 2, "contextMenus": 2,
	"storage": 1, "alarms": 1, "unlimitedStorage": 1,
}

const unknownPermWeight = 5

func permFindings(c *collector, oldP, newP []string, optional bool) {
	added := newItems(oldP, newP)
	if len(added) > 0 {
		total := 0
		for _, p := range added {
			w, ok := permWeights[p]
			if !ok {
				w = unknownPermWeight
			}
			total += w
		}
		label := "New permissions granted"
		if optional {
			total = max(1, total/2)
			label = "New optional permissions requested"
		}
		c.add("PERM_ADDED", min(total, 60), label, added...)
	}
	if gone := newItems(newP, oldP); len(gone) > 0 {
		label := "Permissions removed"
		if optional {
			label = "Optional permissions removed"
		}
		c.add("PERM_REMOVED", 0, label, gone...)
	}
}

func isBroadHost(p string) bool {
	if p == "<all_urls>" || p == "*" {
		return true
	}
	i := strings.Index(p, "://")
	if i < 0 {
		return false
	}
	host := p[i+3:]
	if j := strings.IndexByte(host, '/'); j >= 0 {
		host = host[:j]
	}
	return host == "*"
}

func anyBroad(list []string) bool {
	for _, p := range list {
		if isBroadHost(p) {
			return true
		}
	}
	return false
}

func hostWeight(p string) int {
	if strings.Contains(p, "://*.") || strings.HasPrefix(p, "*.") {
		return 8
	}
	return 4
}

func hostFindings(c *collector, oldH, newH []string, optional bool) {
	added := newItems(oldH, newH)
	var broad, narrow []string
	for _, h := range added {
		if isBroadHost(h) {
			broad = append(broad, h)
		} else {
			narrow = append(narrow, h)
		}
	}
	tag := ""
	if optional {
		tag = " (optional)"
	}
	// Adding another "all sites" pattern when one already existed changes nothing.
	if len(broad) > 0 && !anyBroad(oldH) {
		pts := 40
		if optional {
			pts = 20
		}
		c.add("HOST_BROADENED", pts, "Access to every website"+tag, broad...)
	}
	if len(narrow) > 0 {
		total := 0
		for _, h := range narrow {
			total += hostWeight(h)
		}
		c.add("HOST_ADDED", min(total, 20), "Access to additional sites"+tag, narrow...)
	}
}

func contentScriptFindings(c *collector, o, n *Facts) {
	var oldM, newM []string
	mainOld, mainNew := 0, 0
	for _, cs := range o.ContentScripts {
		oldM = append(oldM, cs.Matches...)
		if cs.World == "MAIN" {
			mainOld++
		}
	}
	for _, cs := range n.ContentScripts {
		newM = append(newM, cs.Matches...)
		if cs.World == "MAIN" {
			mainNew++
		}
	}
	oldM, newM = sorted(oldM), sorted(newM)
	added := newItems(oldM, newM)
	var broad, narrow []string
	for _, m := range added {
		if isBroadHost(m) {
			broad = append(broad, m)
		} else {
			narrow = append(narrow, m)
		}
	}
	if len(broad) > 0 && !anyBroad(oldM) {
		c.add("CONTENT_SCRIPT_BROADENED", 30, "Content scripts now run on every website", broad...)
	}
	if len(narrow) > 0 {
		c.add("CONTENT_SCRIPT_ADDED", min(6*len(narrow), 18), "Content scripts injected into additional sites", narrow...)
	}
	if mainNew > mainOld {
		c.add("CONTENT_SCRIPT_MAIN_WORLD", 10, "Content script runs in the page's own JS world (can read and tamper with page scripts)")
	}
}

func cspRisks(csp map[string]string) []string {
	var out []string
	for ctx, policy := range csp {
		directives := map[string][]string{}
		for _, d := range strings.Split(policy, ";") {
			f := strings.Fields(d)
			if len(f) > 0 {
				directives[strings.ToLower(f[0])] = f[1:]
			}
		}
		vals, ok := directives["script-src"]
		if !ok {
			vals = directives["default-src"]
		}
		for _, v := range vals {
			lv := strings.ToLower(strings.Trim(v, "'"))
			switch {
			case lv == "unsafe-eval":
				out = append(out, ctx+": script-src allows unsafe-eval")
			case lv == "unsafe-inline":
				out = append(out, ctx+": script-src allows unsafe-inline")
			case lv == "*" || lv == "https:" || lv == "http:":
				out = append(out, ctx+": script-src allows any "+strings.TrimSuffix(lv, ":")+" source")
			case strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://"):
				out = append(out, ctx+": script-src loads remote code from "+v)
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func cspFindings(c *collector, o, n *Facts) {
	if added := newItems(cspRisks(o.CSP), cspRisks(n.CSP)); len(added) > 0 {
		c.add("CSP_WEAKENED", min(25*len(added), 50), "Content-Security-Policy now allows riskier script sources", added...)
	}
}

func knownStoreUpdate(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "clients2.google.com", "edge.microsoft.com", "update.googleapis.com":
		return true
	}
	return false
}

func codeFindings(c *collector, o, n *Facts) {
	if d := newItems(o.Domains, n.Domains); len(d) > 0 {
		c.add("NEW_REMOTE_DOMAIN", min(6*len(d), 24), "Code references new remote hosts", d...)
	}
	if ips := newItems(o.IPHosts, n.IPHosts); len(ips) > 0 {
		c.add("NEW_REMOTE_IP", min(15*len(ips), 30), "Code references raw IP addresses", ips...)
	}

	oldDyn, newDyn := o.Code.Eval+o.Code.NewFunction, n.Code.Eval+n.Code.NewFunction
	switch {
	case oldDyn == 0 && newDyn > 0:
		c.add("DYNAMIC_CODE_INTRODUCED", 20, fmt.Sprintf("eval/new Function appeared for the first time (%d call sites)", newDyn))
	case newDyn-oldDyn >= 5:
		c.add("DYNAMIC_CODE_INCREASED", 8, fmt.Sprintf("eval/new Function call sites grew %d -> %d", oldDyn, newDyn))
	}

	oldL := o.Code.ImportScripts + o.Code.ScriptInject
	newL := n.Code.ImportScripts + n.Code.ScriptInject
	if newL > oldL {
		c.add("LOADER_INCREASED", 4, fmt.Sprintf("More script-loading primitives (importScripts / injected <script>): %d -> %d", oldL, newL))
	}

	oldRatio, newRatio := ratio(o.Code.ObfuscatedBytes, o.Code.JSBytes), ratio(n.Code.ObfuscatedBytes, n.Code.JSBytes)
	if len(n.Code.Obfuscated) > len(o.Code.Obfuscated) || newRatio-oldRatio >= 0.25 {
		pts := 25
		if len(o.Code.Obfuscated) > 0 {
			pts = 12
		}
		items := newItems(o.Code.Obfuscated, n.Code.Obfuscated)
		c.add("OBFUSCATION_SPIKE", pts, fmt.Sprintf("Obfuscated-looking code: %d file(s), %.0f%% of script bytes (was %d, %.0f%%)",
			len(n.Code.Obfuscated), newRatio*100, len(o.Code.Obfuscated), oldRatio*100), items...)
	}
}

func ratio(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole)
}

// newItems returns the entries of cur that are not in old (sorted, unique).
func newItems(old, cur []string) []string {
	seen := make(map[string]struct{}, len(old))
	for _, v := range old {
		seen[v] = struct{}{}
	}
	var out []string
	for _, v := range cur {
		if _, ok := seen[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}
