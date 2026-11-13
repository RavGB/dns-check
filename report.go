package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const wrapWidth = 80

// domainResult is one domain in the JSON output: a report, or an error.
type domainResult struct {
	Domain string  `json:"domain"`
	Error  string  `json:"error,omitempty"`
	Report *Report `json:"report,omitempty"`
}

type jsonOutput struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	ExitCode int            `json:"exit_code"`
	Notes    []string       `json:"notes"`
	Results  []domainResult `json:"results"`
}

func writeJSON(w io.Writer, out jsonOutput) error {
	if out.Notes == nil {
		out.Notes = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// writeText prints the plain-text report for one domain.
func writeText(w io.Writer, rep *Report, verbose bool) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	p("DNS and email check for %s\n", rep.Domain)
	if rep.InputNote != "" {
		p("%s", wrap(printable(rep.InputNote), "", ""))
	}
	var names []string
	for _, st := range rep.Resolvers {
		names = append(names, st.Name)
	}
	resolverWord := "resolvers"
	if len(names) == 1 {
		resolverWord = "resolver"
	}
	p("%s", wrap(printable(fmt.Sprintf("Checked %s with %d %s: %s.", rep.CheckedAt.Format("2006-01-02 15:04 MST"), len(names), resolverWord, joinAnd(names))), "", ""))
	p("%s\n", wrap(summaryLine(rep.Findings), "", ""))

	for _, area := range areaOrder {
		var fs []Finding
		for _, f := range rep.Findings {
			if f.Area == area {
				fs = append(fs, f)
			}
		}
		if len(fs) == 0 {
			continue
		}
		// Problems and warnings go first; good news and notes keep their order.
		urgency := func(f Finding) int {
			if f.Severity >= SevWarning {
				return int(f.Severity)
			}
			return 0
		}
		slices.SortStableFunc(fs, func(a, b Finding) int { return urgency(b) - urgency(a) })
		p("%s\n", area)
		for _, f := range fs {
			tag := fmt.Sprintf("  %-10s", "["+f.Severity.String()+"]")
			p("%s", wrap(printable(f.Message), tag, strings.Repeat(" ", len(tag))))
			if verbose && f.Fix != "" {
				p("%s", wrap("Fix: "+printable(f.Fix), strings.Repeat(" ", len(tag)), strings.Repeat(" ", len(tag)+5)))
			}
		}
		p("\n")
	}

	if verbose {
		writeRecords(w, rep)
	}

	p("Could someone send email that looks like it comes from %s?\n", rep.Domain)
	p("%s\n", wrap(rep.Spoofing.Answer+": "+rep.Spoofing.Reason, "  ", "  "))

	p("Top fixes\n")
	if len(rep.TopFixes) == 0 {
		p("  Nothing urgent.\n")
		if len(rep.OptionalFixes) > 0 {
			p("  Optional improvements:\n")
			for i, f := range rep.OptionalFixes {
				num := fmt.Sprintf("  %d. ", i+1)
				p("%s", wrap(upperFirst(strings.TrimPrefix(printable(f), "Optional: ")), num, strings.Repeat(" ", len(num))))
			}
		}
	}
	for i, f := range rep.TopFixes {
		num := fmt.Sprintf("  %d. ", i+1)
		p("%s", wrap(printable(f), num, strings.Repeat(" ", len(num))))
	}
}

// writeRecords lists every record and, where resolvers disagree or failed,
// each resolver's answer.
func writeRecords(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "Records\n")
	for _, r := range rep.Records {
		fmt.Fprintf(w, "  %s, %s\n", r.Label, r.Name)
		if r.Answered && r.Agree {
			writeValues(w, r.Values, "      ")
			continue
		}
		for _, ra := range r.PerResolver {
			fmt.Fprintf(w, "    %s:\n", printable(ra.Resolver))
			if ra.Error != "" {
				fmt.Fprintf(w, "      failed: %s\n", ra.Error)
				continue
			}
			writeValues(w, ra.Values, "      ")
		}
	}
	fmt.Fprintf(w, "\n")
}

func writeValues(w io.Writer, values []string, indent string) {
	if len(values) == 0 {
		fmt.Fprintf(w, "%snothing found\n", indent)
		return
	}
	for _, v := range values {
		fmt.Fprintf(w, "%s%s\n", indent, short(printable(v), wrapWidth-len(indent)))
	}
}

// summaryLine counts findings by severity in plain words.
func summaryLine(fs []Finding) string {
	counts := map[Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return fmt.Sprintf("%d %s", n, one)
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	return fmt.Sprintf("Summary: %s, %s, %s, %s.",
		plural(counts[SevProblem], "problem", "problems"),
		plural(counts[SevWarning], "warning", "warnings"),
		plural(counts[SevNote], "note", "notes"),
		plural(counts[SevOK], "thing looks good", "things look good"))
}

// wrap breaks text into lines of at most wrapWidth characters. The first line
// starts with first, the rest with rest. Every line ends with a newline.
func wrap(text, first, rest string) string {
	var b strings.Builder
	line := first
	empty := true
	for _, word := range strings.Fields(text) {
		if !empty && len(line)+1+len(word) > wrapWidth {
			b.WriteString(line + "\n")
			line, empty = rest, true
		}
		if !empty {
			line += " "
		}
		line += word
		empty = false
	}
	b.WriteString(line + "\n")
	return b.String()
}

// printable replaces control characters, invisible format characters (such
// as right-to-left overrides) and line separators, so text from DNS cannot
// change how the report looks in a terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '?'
		}
		return r
	}, s)
}

// upperFirst capitalises the first letter, so an optional fix reads as a
// sentence once its "Optional: " prefix is removed.
func upperFirst(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}
