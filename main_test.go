package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// runCLI runs the program with args and returns exit code, stdout and stderr.
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errOut, filepath.Join(t.TempDir(), "no-resolv.conf"))
	return code, out.String(), errOut.String()
}

func TestRunUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"-nope", "example.test"},
		{"not a domain"},
		{"-resolvers", "dns.google", "example.test"},
		{"-resolvers", "1.1.1.1:99999", "example.test"},
		{"-selectors", "bad selector", "example.test"},
		{"-timeout", "0s", "example.test"},
		{"-concurrency", "0", "example.test"},
		{"-f", filepath.Join(t.TempDir(), "missing.txt")},
		// Only "system" was asked for, and there is no resolv.conf.
		{"-resolvers", "system", "example.test"},
	}
	for _, args := range cases {
		code, _, stderr := runCLI(t, "", args...)
		if code != exitError {
			t.Errorf("run(%q) = %d, want %d", args, code, exitError)
		}
		if !strings.Contains(stderr, "dns-check -h") {
			t.Errorf("run(%q) stderr %q should point to -h", args, stderr)
		}
	}
}

func TestRunHelpListsEveryFlag(t *testing.T) {
	code, stdout, _ := runCLI(t, "", "-h")
	if code != exitOK {
		t.Errorf("-h exit code = %d, want 0", code)
	}
	for _, want := range []string{"Usage:", "Exit codes:", "dns-check example.com", "https://ravgb.com"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help does not contain %q", want)
		}
	}
	// Build the same flag set run uses and check each flag is documented.
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.file, "f", "", "")
	fs.BoolVar(&o.jsonOut, "json", false, "")
	fs.StringVar(&o.resolvers, "resolvers", "", "")
	fs.StringVar(&o.selectors, "selectors", "", "")
	fs.DurationVar(&o.timeout, "timeout", 0, "")
	fs.IntVar(&o.concurrency, "concurrency", 0, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.version, "version", false, "")
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(stdout, "  -"+f.Name+" ") {
			t.Errorf("help does not document -%s", f.Name)
		}
	})
}

func TestRunVersion(t *testing.T) {
	code, stdout, _ := runCLI(t, "", "-version")
	if code != exitOK || !strings.Contains(stdout, version) {
		t.Errorf("-version: code %d, output %q", code, stdout)
	}
}

func TestRunTextReportGoodDomain(t *testing.T) {
	srv := startFakeDNS(t, goodZone("good.test"))
	code, stdout, stderr := runCLI(t, "", "-resolvers", srv.addr, "https://Good.Test/contact")
	if code != exitOK {
		t.Errorf("exit code = %d, want 0; stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"DNS and email check for good.test",
		"Email security",
		"Could someone send email that looks like it comes from good.test?",
		"  Unlikely: DMARC is set to reject",
		"Top fixes\n  Nothing urgent.",
		"by RavGB, https://ravgb.com",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report does not contain %q:\n%s", want, stdout)
		}
	}
	for _, line := range strings.Split(stdout, "\n") {
		if len(line) > wrapWidth {
			t.Errorf("line longer than %d characters: %q", wrapWidth, line)
		}
	}
}

func TestRunTextReportWithProblems(t *testing.T) {
	d := "weak.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 +all"))
	z.remove("_dmarc."+d, dnsmessage.TypeTXT).add("_dmarc."+d, rrTXT("v=DMARC1; p=none"))
	srv := startFakeDNS(t, z)
	code, stdout, _ := runCLI(t, "", "-v", "-resolvers", srv.addr, d)
	if code != exitFindings {
		t.Errorf("exit code = %d, want %d", code, exitFindings)
	}
	for _, want := range []string{"[problem]", "[warning]", "  Yes: ", "Top fixes\n  1. Change +all", "Fix: ", "Records\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report does not contain %q:\n%s", want, stdout)
		}
	}
}

func TestRunJSON(t *testing.T) {
	d := "nomail.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeMX)
	bad := startFakeDNS(t, z)
	dir := t.TempDir()
	list := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(list, []byte("# my domains\nnomail.test\n\nnomail.test # again\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI(t, "", "-json", "-resolvers", bad.addr, "-f", list)
	if code != exitFindings {
		t.Errorf("exit code = %d, want %d", code, exitFindings)
	}
	var out jsonOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if out.Tool != "dns-check" || out.ExitCode != exitFindings || len(out.Results) != 1 {
		t.Fatalf("unexpected JSON header: %+v", out)
	}
	rep := out.Results[0].Report
	if rep == nil || rep.Domain != d {
		t.Fatalf("report = %+v", out.Results[0])
	}
	if f := findCode(rep, "no_mx"); f == nil || f.Severity != SevWarning {
		t.Errorf("no_mx finding = %+v", f)
	}
	if !strings.Contains(stdout, `"severity": "warning"`) {
		t.Error("severities should be words in JSON")
	}
	if rep.Spoofing.Answer == "" || len(rep.Records) == 0 {
		t.Errorf("JSON report is missing parts: %+v", rep.Spoofing)
	}
}

func TestRunFatalWhenNoResolverAnswers(t *testing.T) {
	code, _, stderr := runCLI(t, "", "-timeout", "300ms", "-resolvers", closedAddr(t), "good.test")
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "none of the resolvers answered") {
		t.Errorf("stderr = %q", stderr)
	}
	code, stdout, _ := runCLI(t, "", "-json", "-timeout", "300ms", "-resolvers", closedAddr(t), "good.test")
	if code != exitError || !strings.Contains(stdout, `"error"`) {
		t.Errorf("JSON fatal: code %d output %s", code, stdout)
	}
}

func TestRunReadsDomainsFromStdin(t *testing.T) {
	srv := startFakeDNS(t, goodZone("good.test"))
	code, stdout, _ := runCLI(t, "good.test\n", "-resolvers", srv.addr, "-f", "-")
	if code != exitOK || !strings.Contains(stdout, "DNS and email check for good.test") {
		t.Errorf("code %d, output:\n%s", code, stdout)
	}
}

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"example.com":                     "example.com",
		"  Example.COM. ":                 "example.com",
		"https://www.example.com/a?b=c":   "www.example.com",
		"http://example.com:8080":         "example.com",
		"someone@example.co.uk":           "example.co.uk",
		"xn--bcher-kva.example":           "xn--bcher-kva.example",
		"_dmarc.example.com":              "_dmarc.example.com",
		"mailto:hello@example.org":        "example.org",
		"https://user@example.net/path#x": "example.net",
	}
	for in, want := range good {
		got, err := normalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "exa mple.com", "-bad.com", "bücher.example", "a..b", strings.Repeat("a", 64) + ".com"} {
		if got, err := normalizeDomain(in); err == nil {
			t.Errorf("normalizeDomain(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseResolvers(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "resolv.conf")
	content := "# comment\nsearch lan\nnameserver 127.0.0.1\nnameserver ::1\nnameserver not-an-ip\n"
	if err := os.WriteFile(conf, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, notes, err := parseResolvers("system, 1.1.1.1, [2001:db8::1]:5353, 2001:db8::2, 1.1.1.1", conf)
	if err != nil || len(notes) != 0 {
		t.Fatalf("err=%v notes=%v", err, notes)
	}
	var names []string
	for _, r := range rs {
		names = append(names, r.Name)
	}
	want := []string{"System resolver (127.0.0.1)", "Cloudflare (1.1.1.1)", "[2001:db8::1]:5353", "2001:db8::2"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	if !slices.Equal(rs[0].Addrs, []string{"127.0.0.1:53", "[::1]:53"}) {
		t.Errorf("system addrs = %q", rs[0].Addrs)
	}

	rs, notes, err = parseResolvers(defaultResolverList, filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(rs) != 3 || len(notes) != 1 || !strings.Contains(notes[0], "system resolver was skipped") {
		t.Errorf("missing resolv.conf: rs=%v notes=%v err=%v", rs, notes, err)
	}
}

// TestNoLongDashes keeps em and en dashes out of the code, help text and README.
func TestNoLongDashes(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("README.md"); err == nil {
		files = append(files, "README.md")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.ContainsRune(b, '\u2014') || bytes.ContainsRune(b, '\u2013') {
			t.Errorf("%s contains an em or en dash", f)
		}
	}
}
