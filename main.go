// Command dns-check checks a domain's DNS and email setup. It asks several
// DNS resolvers at once, compares their answers, and explains in plain words
// what is set up well and what needs fixing.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
)

const version = "0.1.0"

// Exit codes.
const (
	exitOK       = 0 // the check finished and found nothing at warning level or above
	exitFindings = 1 // the check finished and found at least one warning or problem
	exitError    = 2 // usage error or fatal error
)

// domainParallel is how many domains are checked at the same time. The total
// number of lookups in flight is still capped by -concurrency.
const domainParallel = 4

const usageText = `dns-check checks a domain's DNS and email setup.

It asks several DNS resolvers at once, compares their answers, and explains
in plain words what is set up well and what needs fixing: website records,
name servers, email delivery (MX), SPF, DMARC, DKIM, CAA, DNSSEC, MTA-STS,
TLS reporting and BIMI. It ends by answering: could someone send email that
looks like it comes from this domain?

Usage:
  dns-check [flags] domain [domain ...]
  dns-check [flags] -f domains.txt

Examples:
  dns-check example.com
  dns-check -v example.com
  dns-check -json example.com > report.json
  dns-check -resolvers 1.1.1.1,8.8.8.8 -selectors s1,s2 example.com
  dns-check -f domains.txt

Flags:
  -f file          read domains from a file, one per line ("#" starts a
                   comment, "-" reads from standard input)
  -json            print JSON instead of the plain-text report
  -resolvers list  comma separated resolvers as ip or ip:port. The word
                   "system" means the resolver your computer uses, read
                   from /etc/resolv.conf.
                   (default "system,1.1.1.1,8.8.8.8,9.9.9.9")
  -selectors list  comma separated DKIM selector names to try
                   (default "default,selector1,selector2,google,k1,s1,s2,
                   dkim,mail,smtp,mxvault,protonmail,zoho,resend")
  -timeout time    how long to wait for each answer (default 3s)
  -concurrency n   most lookups in flight at once (default 16)
  -v               also show how to fix each finding and list every record
                   with each resolver's answer
  -version         print the version and exit
  -h               show this help

Exit codes:
  0  the check finished and found nothing at warning level or above
  1  the check finished and found at least one warning or problem
  2  usage error, or a fatal error such as no resolver answering

Made by RavGB, https://ravgb.com
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, defaultResolvConf)
	stop()
	os.Exit(code)
}

type options struct {
	file        string
	jsonOut     bool
	resolvers   string
	selectors   string
	timeout     time.Duration
	concurrency int
	verbose     bool
	version     bool
}

// run is the whole program. It returns the exit code.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, resolvConf string) int {
	var o options
	fs := flag.NewFlagSet("dns-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	fs.StringVar(&o.file, "f", "", "read domains from a file")
	fs.BoolVar(&o.jsonOut, "json", false, "print JSON")
	fs.StringVar(&o.resolvers, "resolvers", defaultResolverList, "comma separated resolvers")
	fs.StringVar(&o.selectors, "selectors", strings.Join(defaultSelectors, ","), "comma separated DKIM selectors")
	fs.DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to wait for each answer")
	fs.IntVar(&o.concurrency, "concurrency", 16, "most lookups in flight at once")
	fs.BoolVar(&o.verbose, "v", false, "show fixes and every record")
	fs.BoolVar(&o.version, "version", false, "print the version")

	usageError := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "dns-check: "+format+"\n", a...)
		fmt.Fprintln(stderr, "Run dns-check -h for help.")
		return exitError
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usageText)
			return exitOK
		}
		fmt.Fprintln(stderr, "Run dns-check -h for help.")
		return exitError
	}
	if o.version {
		fmt.Fprintf(stdout, "dns-check %s\n", version)
		return exitOK
	}
	if o.timeout <= 0 {
		return usageError("-timeout must be more than zero")
	}
	if o.concurrency < 1 {
		return usageError("-concurrency must be at least 1")
	}

	var raw []string
	raw = append(raw, fs.Args()...)
	if o.file != "" {
		lines, err := readDomainFile(o.file, stdin)
		if err != nil {
			return usageError("%v", err)
		}
		raw = append(raw, lines...)
	}
	if len(raw) == 0 {
		return usageError("give at least one domain, for example: dns-check example.com")
	}
	var domains []string
	seen := map[string]bool{}
	for _, r := range raw {
		d, err := normalizeDomain(r)
		if err != nil {
			return usageError("%v", err)
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}

	selectors, err := parseSelectors(o.selectors)
	if err != nil {
		return usageError("%v", err)
	}
	resolvers, notes, err := parseResolvers(o.resolvers, resolvConf)
	if !o.jsonOut {
		for _, n := range notes {
			fmt.Fprintln(stderr, "dns-check: "+n)
		}
	}
	if err != nil {
		return usageError("%v", err)
	}

	client := NewClient(o.timeout, o.concurrency)
	cfg := checkConfig{Selectors: selectors, Concurrency: o.concurrency}
	reports := make([]*Report, len(domains))
	errs := make([]error, len(domains))
	runBounded(ctx, len(domains), domainParallel, func(ctx context.Context, i int) {
		reports[i], errs[i] = checkDomain(ctx, client, resolvers, domains[i], cfg)
	})

	code := exitOK
	for i := range domains {
		switch {
		case errs[i] != nil:
			code = exitError
		case reports[i].Worst() >= SevWarning && code == exitOK:
			code = exitFindings
		}
	}

	if o.jsonOut {
		out := jsonOutput{Tool: "dns-check", Version: version, ExitCode: code, Notes: notes}
		for i, d := range domains {
			res := domainResult{Domain: d, Report: reports[i]}
			if errs[i] != nil {
				res.Error = errs[i].Error()
			}
			out.Results = append(out.Results, res)
		}
		if err := writeJSON(stdout, out); err != nil {
			fmt.Fprintf(stderr, "dns-check: %v\n", err)
			return exitError
		}
		return code
	}

	first := true
	for i, d := range domains {
		if errs[i] != nil {
			fmt.Fprintf(stderr, "dns-check: %s: %v\n", d, errs[i])
			continue
		}
		if !first {
			fmt.Fprintf(stdout, "\n%s\n\n", strings.Repeat("=", wrapWidth))
		}
		first = false
		writeText(stdout, reports[i], o.verbose)
	}
	if !first {
		fmt.Fprintf(stdout, "\ndns-check %s by RavGB, https://ravgb.com\n", version)
	}
	return code
}

// readDomainFile reads one domain per line. Blank lines and text after "#"
// are ignored. "-" reads from stdin.
func readDomainFile(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("could not open the domain list: %v", err)
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("could not read the domain list: %v", err)
	}
	return out, nil
}

// normalizeDomain accepts a domain, a URL or an email address and returns
// the bare domain in lowercase.
func normalizeDomain(s string) (string, error) {
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))
	for _, prefix := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("%q is not a domain", orig)
	}
	for _, r := range s {
		if r > 127 {
			return "", fmt.Errorf("%q has non-ASCII letters; use its xn-- form (punycode) instead", orig)
		}
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q is not a domain (expected something like example.com)", orig)
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("%q is not a valid domain", orig)
		}
	}
	return s, nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// parseSelectors reads the -selectors flag.
func parseSelectors(s string) ([]string, error) {
	var out []string
	for _, sel := range strings.Split(s, ",") {
		sel = strings.ToLower(strings.TrimSpace(sel))
		if sel == "" {
			continue
		}
		for _, label := range strings.Split(sel, ".") {
			if !validLabel(label) {
				return nil, fmt.Errorf("%q is not a valid DKIM selector", sel)
			}
		}
		out = append(out, sel)
	}
	return out, nil
}
