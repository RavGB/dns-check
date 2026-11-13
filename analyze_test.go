package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// goodZone is a domain with everything set up well.
func goodZone(d string) *zone {
	z := newZone()
	z.add(d,
		rrSOA("ns1."+d, 2026111301), rrNS("ns1."+d), rrNS("ns2."+d),
		rrA("192.0.2.10"), rrAAAA("2001:db8::10"),
		rrMX(10, "mx1."+d), rrMX(20, "mx2."+d),
		rrTXT("v=spf1 include:_spf."+d+" -all"),
		rrTXT("site-verification=abc123"),
		rrCAA(0, "issue", "letsencrypt.org"),
		rrDS(12345, 13, 2, []byte{0xde, 0xad, 0xbe, 0xef}),
	)
	z.add("www."+d, rrCNAME(d))
	z.add("_spf."+d, rrTXT("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"))
	z.add("_dmarc."+d, rrTXT("v=DMARC1; p=reject; rua=mailto:dmarc@"+d))
	z.add("google._domainkey."+d, rrTXT("v=DKIM1; k=rsa; ", "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"))
	z.add("_mta-sts."+d, rrTXT("v=STSv1; id=20261113"))
	z.add("_smtp._tls."+d, rrTXT("v=TLSRPTv1; rua=mailto:tls@"+d))
	z.add("default._bimi."+d, rrTXT("v=BIMI1; l=https://"+d+"/logo.svg"))
	return z
}

// check runs the full check for domain with one fake resolver per zone.
func check(t *testing.T, domain string, zones ...*zone) *Report {
	t.Helper()
	var resolvers []Resolver
	for _, z := range zones {
		resolvers = append(resolvers, startFakeDNS(t, z).resolver())
	}
	rep, err := checkDomain(context.Background(), NewClient(2*time.Second, 8), resolvers, domain, checkConfig{Selectors: defaultSelectors, Concurrency: 8})
	if err != nil {
		t.Fatalf("checkDomain: %v", err)
	}
	return rep
}

func findCode(rep *Report, code string) *Finding {
	for i := range rep.Findings {
		if rep.Findings[i].Code == code {
			return &rep.Findings[i]
		}
	}
	return nil
}

func wantFinding(t *testing.T, rep *Report, code string, sev Severity, contains ...string) *Finding {
	t.Helper()
	f := findCode(rep, code)
	if f == nil {
		t.Fatalf("no %q finding; got:\n%s", code, dumpFindings(rep))
	}
	if f.Severity != sev {
		t.Errorf("%s severity = %v, want %v", code, f.Severity, sev)
	}
	for _, c := range contains {
		if !strings.Contains(f.Message, c) {
			t.Errorf("%s message %q does not mention %q", code, f.Message, c)
		}
	}
	return f
}

func dumpFindings(rep *Report) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		b.WriteString("  " + f.Severity.String() + " " + f.Code + ": " + f.Message + "\n")
	}
	return b.String()
}

func TestGoodSetup(t *testing.T) {
	d := "good.test"
	rep := check(t, d, goodZone(d), goodZone(d))
	if w := rep.Worst(); w != SevOK {
		t.Errorf("worst = %v, want ok; findings:\n%s", w, dumpFindings(rep))
	}
	for _, code := range []string{"apex_ok", "www_ok", "ns_ok", "mx_ok", "spf_ok", "dmarc_reject", "dmarc_rua",
		"dkim_found", "mta_sts_ok", "tls_rpt_ok", "bimi_ok", "caa_ok", "dnssec_on", "resolvers_agree"} {
		wantFinding(t, rep, code, SevOK)
	}
	if rep.Spoofing.Answer != "Unlikely" {
		t.Errorf("spoofing = %+v, want Unlikely", rep.Spoofing)
	}
	if rep.SPF == nil || rep.SPF.Lookups != 1 || !rep.SPF.LookupsComplete || rep.SPF.All != "-" {
		t.Errorf("SPF summary = %+v", rep.SPF)
	}
	if rep.DMARC == nil || rep.DMARC.Policy != "reject" || len(rep.DMARC.Reports) != 1 {
		t.Errorf("DMARC summary = %+v", rep.DMARC)
	}
	if len(rep.DKIMSelectors) != 1 || rep.DKIMSelectors[0] != "google" {
		t.Errorf("DKIM selectors = %v, want [google]", rep.DKIMSelectors)
	}
	if !rep.DNSSEC {
		t.Error("DNSSEC = false, want true")
	}
	if len(rep.TopFixes) != 0 {
		t.Errorf("top fixes = %q, want none", rep.TopFixes)
	}
	wantFinding(t, rep, "www_ok", SevOK, "www.good.test", "good.test")
	wantFinding(t, rep, "caa_ok", SevOK, "letsencrypt.org")
}

func TestSPFPlusAll(t *testing.T) {
	d := "open.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 +all"))
	z.remove("_dmarc."+d, dnsmessage.TypeTXT)
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_plus_all", SevProblem, "+all")
	wantFinding(t, rep, "dmarc_missing", SevProblem)
	if rep.Spoofing.Answer != "Yes" || !strings.Contains(rep.Spoofing.Reason, "+all") {
		t.Errorf("spoofing = %+v, want Yes because of +all", rep.Spoofing)
	}
	if len(rep.TopFixes) == 0 || !strings.Contains(rep.TopFixes[0], "+all") {
		t.Errorf("first top fix = %q, want the +all fix", rep.TopFixes)
	}
}

func TestSPFPlusAllBeatsDMARCReject(t *testing.T) {
	d := "plus.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 +all"))
	rep := check(t, d, z)
	if rep.Spoofing.Answer != "Yes" {
		t.Errorf("spoofing = %+v, want Yes: +all passes SPF for anyone, which satisfies DMARC", rep.Spoofing)
	}
}

func TestTwoSPFRecords(t *testing.T) {
	d := "twice.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 -all"), rrTXT("v=spf1 include:_spf."+d+" ~all"))
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_multiple", SevProblem, "2 SPF records")
	if rep.SPF != nil {
		t.Errorf("SPF summary = %+v, want nil when the record is ambiguous", rep.SPF)
	}
	// DMARC reject still protects the visible From address.
	if rep.Spoofing.Answer != "Unlikely" {
		t.Errorf("spoofing = %+v, want Unlikely", rep.Spoofing)
	}
}

func TestDMARCMonitoringOnly(t *testing.T) {
	d := "watch.test"
	z := goodZone(d)
	z.remove("_dmarc."+d, dnsmessage.TypeTXT).add("_dmarc."+d, rrTXT("v=DMARC1; p=none"))
	rep := check(t, d, z)
	f := wantFinding(t, rep, "dmarc_none", SevWarning, "monitoring only")
	if !strings.Contains(f.Fix, "rua=") {
		t.Errorf("dmarc_none fix %q should say to add rua first", f.Fix)
	}
	wantFinding(t, rep, "dmarc_no_rua", SevNote)
	if rep.Spoofing.Answer != "Partly" || !strings.Contains(rep.Spoofing.Reason, "p=none") {
		t.Errorf("spoofing = %+v, want Partly because of p=none", rep.Spoofing)
	}
	// Without enforcement, a missing BIMI record is not worth mentioning.
	if findCode(rep, "bimi_missing") != nil {
		t.Error("bimi_missing reported while DMARC is not enforcing")
	}
}

func TestDMARCQuarantineAndPartialPct(t *testing.T) {
	d := "pct.test"
	z := goodZone(d)
	z.remove("_dmarc."+d, dnsmessage.TypeTXT).add("_dmarc."+d, rrTXT("v=DMARC1; p=quarantine; pct=25; sp=none; rua=mailto:r@pct.test"))
	rep := check(t, d, z)
	wantFinding(t, rep, "dmarc_quarantine", SevOK)
	wantFinding(t, rep, "dmarc_pct", SevWarning, "25%")
	wantFinding(t, rep, "dmarc_sp_none", SevWarning)
	if rep.Spoofing.Answer != "Partly" {
		t.Errorf("spoofing = %+v, want Partly with pct=25", rep.Spoofing)
	}
}

func TestNoMXRecords(t *testing.T) {
	d := "nomail.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeMX)
	rep := check(t, d, z)
	wantFinding(t, rep, "no_mx", SevWarning, "no MX records")
	// MTA-STS and TLS-RPT only matter for domains that receive email, but
	// this zone has them, so they are still reported as good.
	wantFinding(t, rep, "mta_sts_ok", SevOK)
}

func TestNullMX(t *testing.T) {
	d := "nullmx.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeMX).add(d, rrMX(0, "."))
	z.remove("_mta-sts."+d, dnsmessage.TypeTXT)
	rep := check(t, d, z)
	wantFinding(t, rep, "mx_null", SevOK)
	if findCode(rep, "no_mx") != nil || findCode(rep, "mta_sts_missing") != nil {
		t.Errorf("null MX should not trigger no_mx or mta_sts_missing:\n%s", dumpFindings(rep))
	}
}

func TestNoSPFNoDMARC(t *testing.T) {
	d := "bare.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT)
	z.remove("_dmarc."+d, dnsmessage.TypeTXT)
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_missing", SevProblem)
	wantFinding(t, rep, "dmarc_missing", SevProblem)
	if rep.Spoofing.Answer != "Yes" {
		t.Errorf("spoofing = %+v, want Yes", rep.Spoofing)
	}
	// SPF comes before DMARC in the fix list: DMARC needs SPF or DKIM to pass.
	if len(rep.TopFixes) < 2 || !strings.HasPrefix(rep.TopFixes[0], "Add one TXT record at bare.test") {
		t.Errorf("top fixes = %q, want the SPF fix first", rep.TopFixes)
	}
}

func TestSPFTooManyLookups(t *testing.T) {
	d := "heavy.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 include:a.heavy.test include:b.heavy.test include:c.heavy.test -all"))
	z.add("a.heavy.test", rrTXT("v=spf1 a mx ptr -all"))
	z.add("b.heavy.test", rrTXT("v=spf1 a mx ptr -all"))
	z.add("c.heavy.test", rrTXT("v=spf1 include:d.heavy.test -all"))
	z.add("d.heavy.test", rrTXT("v=spf1 a mx -all"))
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_too_many_lookups", SevProblem, "12 DNS lookups")
	if rep.SPF == nil || rep.SPF.Lookups != 12 {
		t.Errorf("SPF summary = %+v, want 12 lookups", rep.SPF)
	}
}

func TestSPFIncludeWithoutRecord(t *testing.T) {
	d := "gone.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 include:old-provider.test -all"))
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_include_missing", SevWarning, "old-provider.test")
}

func TestResolversDisagree(t *testing.T) {
	d := "moving.test"
	oldZone := goodZone(d)
	moved := goodZone(d)
	moved.remove(d, dnsmessage.TypeMX).add(d, rrMX(10, "mx.newhost.test"))
	moved.remove(d, dnsmessage.TypeA).add(d, rrA("192.0.2.99"))

	s1, s2, s3 := startFakeDNS(t, oldZone), startFakeDNS(t, oldZone), startFakeDNS(t, moved)
	resolvers := []Resolver{s1.resolver(), s2.resolver(), s3.resolver()}
	rep, err := checkDomain(context.Background(), NewClient(2*time.Second, 8), resolvers, d, checkConfig{Selectors: defaultSelectors, Concurrency: 8})
	if err != nil {
		t.Fatal(err)
	}
	f := wantFinding(t, rep, "resolvers_disagree", SevWarning, "mail servers (MX)", s1.addr, s2.addr, s3.addr, "mx.newhost.test", "still spreading")
	if !strings.Contains(f.Message, s1.addr+" and "+s2.addr+" see") || !strings.Contains(f.Message, s3.addr+" sees") {
		t.Errorf("message does not group resolvers by answer: %s", f.Message)
	}
	// Different website addresses are only a note: CDNs do that on purpose.
	wantFinding(t, rep, "addresses_differ", SevNote, "192.0.2.99")
	// The majority answer is used for the analysis.
	if mx := rep.record("mx"); mx.Agree || len(mx.Values) != 2 {
		t.Errorf("mx record = %+v, want the two old MX hosts and agree=false", mx)
	}
	if findCode(rep, "resolvers_agree") != nil {
		t.Error("resolvers_agree reported while they disagree")
	}
}

func TestRecordMissingOnSomeResolvers(t *testing.T) {
	d := "fresh.test"
	before := goodZone(d)
	before.remove("_dmarc."+d, dnsmessage.TypeTXT)
	rep := check(t, d, goodZone(d), before)
	wantFinding(t, rep, "resolvers_disagree", SevWarning, "DMARC", "sees nothing")
}

func TestUnreachableResolverIsReportedAndSkipped(t *testing.T) {
	d := "good.test"
	srv := startFakeDNS(t, goodZone(d))
	dead := Resolver{Name: "Dead resolver", Addrs: []string{closedAddr(t)}}
	rep, err := checkDomain(context.Background(), NewClient(300*time.Millisecond, 8), []Resolver{dead, srv.resolver()}, d,
		checkConfig{Selectors: defaultSelectors, Concurrency: 8})
	if err != nil {
		t.Fatalf("checkDomain: %v", err)
	}
	wantFinding(t, rep, "resolver_unreachable", SevNote, "Dead resolver", "carried on")
	wantFinding(t, rep, "dmarc_reject", SevOK)
	wantFinding(t, rep, "single_resolver", SevNote)
	if rep.Resolvers[0].Usable || !rep.Resolvers[1].Usable {
		t.Errorf("resolver statuses = %+v", rep.Resolvers)
	}
	if rep.Spoofing.Answer != "Unlikely" {
		t.Errorf("spoofing = %+v", rep.Spoofing)
	}
}

func TestAllResolversUnreachable(t *testing.T) {
	dead := []Resolver{{Name: "one", Addrs: []string{closedAddr(t)}}, {Name: "two", Addrs: []string{closedAddr(t)}}}
	_, err := checkDomain(context.Background(), NewClient(300*time.Millisecond, 8), dead, "good.test", checkConfig{Selectors: []string{"s1"}, Concurrency: 8})
	if err == nil || !strings.Contains(err.Error(), "none of the resolvers answered") {
		t.Errorf("err = %v, want 'none of the resolvers answered'", err)
	}
}

func TestDomainNotFound(t *testing.T) {
	rep := check(t, "nothere.test", goodZone("other.test"))
	wantFinding(t, rep, "domain_not_found", SevProblem, "not found")
	if rep.Spoofing.Answer != "Not sure" {
		t.Errorf("spoofing = %+v", rep.Spoofing)
	}
	if len(rep.Findings) != 1 {
		t.Errorf("want only the not-found finding, got:\n%s", dumpFindings(rep))
	}
}

func TestTruncatedAnswersStillWork(t *testing.T) {
	d := "big.test"
	z := goodZone(d)
	z.truncate[d] = true
	srv := startFakeDNS(t, z)
	rep, err := checkDomain(context.Background(), NewClient(2*time.Second, 8), []Resolver{srv.resolver()}, d,
		checkConfig{Selectors: defaultSelectors, Concurrency: 8})
	if err != nil {
		t.Fatal(err)
	}
	wantFinding(t, rep, "spf_ok", SevOK)
	if srv.tcpQueries.Load() == 0 {
		t.Error("no TCP queries were made")
	}
	txt := rep.record("txt")
	if len(txt.PerResolver) != 1 || !txt.PerResolver[0].UsedTCP {
		t.Errorf("txt lookup did not record TCP use: %+v", txt.PerResolver)
	}
}

func TestDanglingWWW(t *testing.T) {
	d := "dangle.test"
	z := goodZone(d)
	z.remove("www."+d, dnsmessage.TypeCNAME).add("www."+d, rrCNAME("old-site.host.test"))
	rep := check(t, d, z)
	wantFinding(t, rep, "www_dangling", SevWarning, "old-site.host.test")
}

func TestSpoofVerdictTable(t *testing.T) {
	cases := []struct {
		spf    spfState
		dmarc  dmarcState
		answer string
	}{
		{spfHard, dmarcState{known: true, present: true, policy: "reject", pct: 100}, "Unlikely"},
		{spfMissing, dmarcState{known: true, present: true, policy: "reject", pct: 100}, "Unlikely"},
		{spfSoft, dmarcState{known: true, present: true, policy: "quarantine", pct: 100}, "Unlikely"},
		{spfHard, dmarcState{known: true, present: true, policy: "reject", pct: 50}, "Partly"},
		{spfHard, dmarcState{known: true, present: true, policy: "none", pct: 100}, "Partly"},
		{spfSoft, dmarcState{known: true}, "Partly"},
		{spfNeutral, dmarcState{known: true}, "Yes"},
		{spfMissing, dmarcState{known: true, present: true, policy: "none", pct: 100}, "Yes"},
		{spfBroken, dmarcState{known: true, present: true}, "Yes"},
		{spfPlusAll, dmarcState{known: true, present: true, policy: "reject", pct: 100}, "Yes"},
		{spfUnknown, dmarcState{known: true}, "Not sure"},
	}
	for _, tc := range cases {
		v := spoofVerdict("x.test", tc.spf, tc.dmarc)
		if v.Answer != tc.answer {
			t.Errorf("spoofVerdict(%v, %+v) = %+v, want %s", tc.spf, tc.dmarc, v, tc.answer)
		}
		if v.Reason == "" || !strings.HasSuffix(v.Reason, ".") {
			t.Errorf("reason %q should be a full sentence", v.Reason)
		}
	}
}

func TestTopFixesOrder(t *testing.T) {
	fs := []Finding{
		{Severity: SevNote, Code: "caa_missing", Fix: "caa"},
		{Severity: SevWarning, Code: "no_mx", Fix: "mx"},
		{Severity: SevProblem, Code: "dmarc_missing", Fix: "dmarc"},
		{Severity: SevProblem, Code: "spf_plus_all", Fix: "plus"},
		{Severity: SevWarning, Code: "resolvers_disagree", Fix: "wait"},
		{Severity: SevWarning, Code: "resolvers_disagree", Fix: "wait"},
		{Severity: SevOK, Code: "mx_ok"},
	}
	top, optional := topFixes(fs)
	want := []string{"plus", "dmarc", "mx", "wait"}
	if strings.Join(top, ",") != strings.Join(want, ",") {
		t.Errorf("top = %q, want %q", top, want)
	}
	if len(optional) != 0 {
		t.Errorf("optional = %q, want none while there are urgent fixes", optional)
	}
	top, optional = topFixes(fs[:1])
	if len(top) != 0 || len(optional) != 1 {
		t.Errorf("notes only: top=%q optional=%q", top, optional)
	}
}
