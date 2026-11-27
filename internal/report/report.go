// Package report renders analysis results for humans.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/radnyxx/driftwatch/internal/analyze"
)

const maxItems = 8

type painter bool

func (p painter) wrap(code, s string) string {
	if !p {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) severity(sev string, s string) string {
	switch sev {
	case "critical":
		return p.wrap("1;31", s)
	case "high":
		return p.wrap("31", s)
	case "medium":
		return p.wrap("33", s)
	case "low":
		return p.wrap("36", s)
	}
	return p.wrap("2", s)
}

func label(f *analyze.Facts) string {
	if f.Version == "" {
		return "?"
	}
	return f.Version
}

// Text writes a human-readable diff report.
func Text(w io.Writer, r *analyze.Result, color bool) {
	p := painter(color)
	fmt.Fprintf(w, "%s  %s  %s -> %s\n", p.wrap("1", "driftwatch"), r.New.Name, label(r.Old), label(r.New))
	fmt.Fprintf(w, "risk %d/100  %s\n\n", r.Score, p.severity(r.Verdict, strings.ToUpper(r.Verdict)))

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "no risky changes detected")
	}
	for _, f := range r.Findings {
		tag := fmt.Sprintf("[%s %+d]", strings.ToUpper(string(f.Severity)), f.Points)
		fmt.Fprintf(w, "%s %s  %s\n", p.severity(string(f.Severity), tag), f.Code, f.Message)
		for i, it := range f.Items {
			if i == maxItems {
				fmt.Fprintf(w, "      ... +%d more\n", len(f.Items)-maxItems)
				break
			}
			fmt.Fprintf(w, "      - %s\n", it)
		}
	}
	fmt.Fprintf(w, "\nfiles: +%d added  -%d removed  ~%d modified\n", r.Files.Added, r.Files.Removed, r.Files.Modified)
}
