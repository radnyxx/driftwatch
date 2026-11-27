// driftwatch compares successive releases of a browser extension and flags
// changes that make it riskier: new permissions, broader site access, weaker
// CSP, new remote endpoints, dynamic code and obfuscation spikes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/radnyxx/driftwatch/internal/analyze"
	"github.com/radnyxx/driftwatch/internal/artifact"
	"github.com/radnyxx/driftwatch/internal/report"
)

const version = "0.1.0"

const usage = `driftwatch ` + version + ` - spot extensions that turn risky between releases

usage:
  driftwatch diff [flags] <old> <new>        compare two releases
  driftwatch timeline [flags] <v1> <v2> ...  risk trend across releases (oldest first)
  driftwatch inspect <path>                  dump the facts extracted from one release
  driftwatch version

<old>/<new> may be a .crx, .xpi, .zip or an unpacked extension directory.
Flags go before the paths.

flags (diff, timeline):
  -json                 machine-readable output
  -fail-on N            exit 2 if a risk score is >= N (CI gate)
  -ignore-domain HOST   do not report HOST or its subdomains (repeatable)
`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type commonFlags struct {
	asJSON bool
	failOn int
	ignore multiFlag
}

func newFlagSet(name string, c *commonFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&c.asJSON, "json", false, "")
	fs.IntVar(&c.failOn, "fail-on", 0, "")
	fs.Var(&c.ignore, "ignore-domain", "")
	return fs
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 64
	}
	switch args[0] {
	case "diff":
		return cmdDiff(args[1:])
	case "timeline":
		return cmdTimeline(args[1:])
	case "inspect":
		return cmdInspect(args[1:])
	case "version", "-v", "--version":
		fmt.Println("driftwatch", version)
		return 0
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
	return 64
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "driftwatch:", err)
	return 1
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func writeJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fail(err)
	}
	return 0
}

func cmdDiff(args []string) int {
	var c commonFlags
	fs := newFlagSet("diff", &c)
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		fmt.Fprint(os.Stderr, usage)
		return 64
	}
	oldB, err := artifact.Load(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	newB, err := artifact.Load(fs.Arg(1))
	if err != nil {
		return fail(err)
	}
	res, err := analyze.Compare(oldB, newB, analyze.Options{IgnoreDomains: c.ignore})
	if err != nil {
		return fail(err)
	}
	if c.asJSON {
		if code := writeJSON(res); code != 0 {
			return code
		}
	} else {
		report.Text(os.Stdout, res, useColor())
	}
	if c.failOn > 0 && res.Score >= c.failOn {
		return 2
	}
	return 0
}

type timelineRow struct {
	Version     string `json:"version"`
	Permissions int    `json:"permissions"`
	Hosts       int    `json:"hosts"`
	Domains     int    `json:"remote_domains"`
	Obfuscated  int    `json:"obfuscated_files"`
	Risk        int    `json:"risk_vs_previous"`
	Verdict     string `json:"verdict"`
}

func cmdTimeline(args []string) int {
	var c commonFlags
	fs := newFlagSet("timeline", &c)
	if err := fs.Parse(args); err != nil || fs.NArg() < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 64
	}
	opt := analyze.Options{IgnoreDomains: c.ignore}
	var rows []timelineRow
	var prevF *analyze.Facts
	worst := 0
	for _, p := range fs.Args() {
		b, err := artifact.Load(p)
		if err != nil {
			return fail(err)
		}
		f, err := analyze.Analyze(b, opt)
		if err != nil {
			return fail(err)
		}
		row := timelineRow{
			Version:     f.Version,
			Permissions: len(f.Permissions) + len(f.OptionalPermissions),
			Hosts:       len(f.Hosts) + len(f.OptionalHosts),
			Domains:     len(f.Domains) + len(f.IPHosts),
			Obfuscated:  len(f.Code.Obfuscated),
			Verdict:     "-",
		}
		if prevF != nil {
			res := analyze.CompareFacts(prevF, f, analyze.FileChanges{})
			row.Risk, row.Verdict = res.Score, res.Verdict
			worst = max(worst, res.Score)
		}
		rows = append(rows, row)
		prevF = f
	}
	if c.asJSON {
		if code := writeJSON(rows); code != 0 {
			return code
		}
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "VERSION\tPERMS\tHOSTS\tREMOTE\tOBFUSC\tRISK\tVERDICT")
		for _, r := range rows {
			risk := "-"
			if r.Verdict != "-" {
				risk = fmt.Sprint(r.Risk)
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\t%s\n", r.Version, r.Permissions, r.Hosts, r.Domains, r.Obfuscated, risk, r.Verdict)
		}
		tw.Flush()
	}
	if c.failOn > 0 && worst >= c.failOn {
		return 2
	}
	return 0
}

func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 64
	}
	b, err := artifact.Load(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	f, err := analyze.Analyze(b, analyze.Options{})
	if err != nil {
		return fail(err)
	}
	return writeJSON(f)
}
