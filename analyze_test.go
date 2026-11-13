package main

import (
	"context"
	"slices"
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
	// SPF is fine, but without an enforcing DMARC policy nothing checks the
	// From line people see, so the honest answer is Yes.
	if rep.Spoofing.Answer != "Yes" || !strings.Contains(rep.Spoofing.Reason, "p=none") || !strings.Contains(rep.Spoofing.Reason, "From line") {
		t.Errorf("spoofing = %+v, want Yes because of p=none", rep.Spoofing)
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
	heavy := func() *zone {
		z := goodZone(d)
		z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 include:a.heavy.test include:b.heavy.test include:c.heavy.test -all"))
		z.add("a.heavy.test", rrTXT("v=spf1 a mx ptr -all"))
		z.add("b.heavy.test", rrTXT("v=spf1 a mx ptr -all"))
		z.add("c.heavy.test", rrTXT("v=spf1 include:d.heavy.test -all"))
		z.add("d.heavy.test", rrTXT("v=spf1 a mx -all"))
		return z
	}
	rep := check(t, d, heavy())
	wantFinding(t, rep, "spf_too_many_lookups", SevProblem, "12 DNS lookups")
	if rep.SPF == nil || rep.SPF.Lookups != 12 {
		t.Errorf("SPF summary = %+v, want 12 lookups", rep.SPF)
	}
	// Over 10 lookups is a permanent error, so SPF is broken, not "ok".
	if findCode(rep, "spf_ok") != nil {
		t.Errorf("spf_ok reported for a record over the lookup limit:\n%s", dumpFindings(rep))
	}
	rep = check(t, d, heavy().remove("_dmarc."+d, dnsmessage.TypeTXT))
	if rep.Spoofing.Answer != "Yes" || !strings.Contains(rep.Spoofing.Reason, "SPF setup is broken") {
		t.Errorf("spoofing without DMARC = %+v, want Yes because SPF is broken", rep.Spoofing)
	}
}

func TestSPFIncludeWithoutRecord(t *testing.T) {
	d := "gone.test"
	gone := func() *zone {
		z := goodZone(d)
		z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 include:old-provider.test -all"))
		return z
	}
	rep := check(t, d, gone())
	wantFinding(t, rep, "spf_include_missing", SevProblem, "old-provider.test")
	if findCode(rep, "spf_ok") != nil {
		t.Errorf("spf_ok reported while an include has no SPF record:\n%s", dumpFindings(rep))
	}
	rep = check(t, d, gone().remove("_dmarc."+d, dnsmessage.TypeTXT))
	if rep.Spoofing.Answer != "Yes" || !strings.Contains(rep.Spoofing.Reason, "SPF setup is broken") {
		t.Errorf("spoofing without DMARC = %+v, want Yes because SPF is broken", rep.Spoofing)
	}
}

func TestSPFTermsAfterAll(t *testing.T) {
	d := "after.test"
	z := goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 +all -all"))
	z.remove("_dmarc."+d, dnsmessage.TypeTXT).add("_dmarc."+d, rrTXT("v=DMARC1; p=none"))
	rep := check(t, d, z)
	wantFinding(t, rep, "spf_plus_all", SevProblem)
	wantFinding(t, rep, "spf_after_all", SevWarning, "-all", "ignored")
	if findCode(rep, "spf_ok") != nil {
		t.Errorf("spf_ok reported for +all -all:\n%s", dumpFindings(rep))
	}
	if rep.SPF.All != "+" || rep.Spoofing.Answer != "Yes" {
		t.Errorf("SPF all = %q, spoofing = %+v; want + and Yes", rep.SPF.All, rep.Spoofing)
	}

	d = "first.test"
	z = goodZone(d)
	z.remove(d, dnsmessage.TypeTXT).add(d, rrTXT("v=spf1 include:_spf.first.test ~all include:big.first.test -all"))
	// big.first.test would push the count over 10 if it were counted.
	z.add("big.first.test", rrTXT("v=spf1 a mx ptr a:x.test mx:x.test ptr:x.test exists:x.test a:y.test mx:y.test ptr:y.test -all"))
	rep = check(t, d, z)
	if rep.SPF.All != "~" || rep.SPF.Lookups != 1 {
		t.Errorf("SPF summary = %+v, want ~all and 1 lookup", rep.SPF)
	}
	if findCode(rep, "spf_too_many_lookups") != nil {
		t.Errorf("terms after ~all were counted:\n%s", dumpFindings(rep))
	}
	f := wantFinding(t, rep, "spf_after_all", SevWarning, "include:big.first.test")
	if !strings.Contains(f.Fix, "in front of ~all") {
		t.Errorf("spf_after_all fix = %q", f.Fix)
	}
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
		{spfBroken, dmarcState{known: true, present: true, policy: "reject", pct: 100}, "Unlikely"},
		{spfHard, dmarcState{known: true, present: true, policy: "reject", pct: 50}, "Partly"},
		// Without an enforcing DMARC policy nothing checks the visible From
		// line, whatever SPF says.
		{spfHard, dmarcState{known: true, present: true, policy: "none", pct: 100}, "Yes"},
		{spfSoft, dmarcState{known: true}, "Yes"},
		{spfRedirect, dmarcState{known: true, present: true}, "Yes"},
		{spfNeutral, dmarcState{known: true}, "Yes"},
		{spfMissing, dmarcState{known: true, present: true, policy: "none", pct: 100}, "Yes"},
		{spfBroken, dmarcState{known: true, present: true}, "Yes"},
		{spfBroken, dmarcState{known: true}, "Yes"},
		{spfPlusAll, dmarcState{known: true, present: true, policy: "reject", pct: 100}, "Yes"},
		{spfUnknown, dmarcState{known: true}, "Not sure"},
		{spfHard, dmarcState{}, "Not sure"},
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
	v := spoofVerdict("x.test", spfHard, dmarcState{known: true, present: true, policy: "none", tag: "sp", pct: 100})
	if !strings.Contains(v.Reason, "sp=none") || !strings.Contains(v.Reason, "hidden sender address") {
		t.Errorf("reason %q should name sp=none and say what SPF alone does", v.Reason)
	}
}

func TestSubdomainUsesParentPolicies(t *testing.T) {
	z := goodZone("good.test")
	z.add("shop.good.test", rrA("192.0.2.20"))
	rep := check(t, "shop.good.test", z, z)
	f := wantFinding(t, rep, "dmarc_reject", SevOK, "_dmarc.good.test", "p=reject")
	if !strings.Contains(f.Message, "no DMARC record of its own") {
		t.Errorf("dmarc_reject should say the parent's record applies: %q", f.Message)
	}
	if rep.DMARC == nil || rep.DMARC.FoundAt != "_dmarc.good.test" || rep.DMARC.AppliedPolicy != "reject" {
		t.Errorf("DMARC summary = %+v", rep.DMARC)
	}
	if rep.Spoofing.Answer != "Unlikely" {
		t.Errorf("spoofing = %+v, want Unlikely from the parent's p=reject", rep.Spoofing)
	}
	wantFinding(t, rep, "caa_ok", SevOK, "good.test", "letsencrypt.org")
	wantFinding(t, rep, "dnssec_on", SevOK, "DNSSEC is on for good.test")
	wantFinding(t, rep, "ns_none", SevNote, "parent domain")
	if !rep.DNSSEC {
		t.Error("DNSSEC = false, want true from the parent's DS record")
	}
	for _, code := range []string{"www_missing", "www_dangling", "dmarc_missing", "caa_missing", "dnssec_off"} {
		if findCode(rep, code) != nil {
			t.Errorf("%s reported for a subdomain covered by its parent:\n%s", code, dumpFindings(rep))
		}
	}
	if strings.Contains(strings.Join(rep.TopFixes, " "), "www.shop") {
		t.Errorf("top fixes mention www.shop: %q", rep.TopFixes)
	}

	// The parent's subdomain policy (sp=) wins over its main policy.
	z2 := goodZone("good.test")
	z2.remove("_dmarc.good.test", dnsmessage.TypeTXT).add("_dmarc.good.test", rrTXT("v=DMARC1; p=reject; sp=none"))
	z2.add("shop.good.test", rrA("192.0.2.20"))
	rep = check(t, "shop.good.test", z2)
	wantFinding(t, rep, "dmarc_none", SevWarning, "sp=none", "_dmarc.good.test")
	if rep.Spoofing.Answer != "Yes" || !strings.Contains(rep.Spoofing.Reason, "sp=none") {
		t.Errorf("spoofing = %+v, want Yes because of sp=none", rep.Spoofing)
	}

	// Its own record wins over the parent's.
	z3 := goodZone("good.test")
	z3.add("shop.good.test", rrA("192.0.2.20"))
	z3.add("_dmarc.shop.good.test", rrTXT("v=DMARC1; p=none"))
	rep = check(t, "shop.good.test", z3)
	wantFinding(t, rep, "dmarc_none", SevWarning, "DMARC is set to p=none")
	if rep.DMARC.FoundAt != "_dmarc.shop.good.test" {
		t.Errorf("DMARC found at %q", rep.DMARC.FoundAt)
	}
}

func TestSubdomainWithoutAnyDMARC(t *testing.T) {
	z := goodZone("good.test")
	z.remove("_dmarc.good.test", dnsmessage.TypeTXT)
	z.add("shop.good.test", rrA("192.0.2.20"))
	rep := check(t, "shop.good.test", z)
	wantFinding(t, rep, "dmarc_missing", SevProblem, "Neither shop.good.test nor good.test has one")
}

func TestNameInsideADelegatedSubdomain(t *testing.T) {
	// eu.good.test is its own zone (it has name servers) and is not signed,
	// so a.eu.good.test is not covered by good.test's DNSSEC. DMARC still
	// comes from good.test, the nearest parent that has a record.
	z := goodZone("good.test")
	z.add("eu.good.test", rrNS("ns1.other.test"))
	z.add("a.eu.good.test", rrA("192.0.2.30"))
	rep := check(t, "a.eu.good.test", z)
	wantFinding(t, rep, "dnssec_off", SevNote)
	if rep.DNSSEC {
		t.Error("DNSSEC = true, want false: the zone eu.good.test has no DS record")
	}
	wantFinding(t, rep, "dmarc_reject", SevOK, "_dmarc.good.test")
}

func TestParentNames(t *testing.T) {
	cases := map[string][]string{
		"example.com":             nil,
		"shop.example.com":        {"example.com"},
		"a.b.example.com":         {"b.example.com", "example.com"},
		"example.co.uk":           nil,
		"mail.example.co.uk":      {"example.co.uk"},
		"example.co.za":           nil,
		"shop.example.on.ca":      {"example.on.ca"},
		"agency.gc.ca":            nil,
		"shop.example.ca":         {"example.ca"},
		"a.b.c.d.e.f.example.com": {"b.c.d.e.f.example.com", "c.d.e.f.example.com", "d.e.f.example.com", "e.f.example.com", "example.com"},
	}
	for in, want := range cases {
		if got := parentNames(in); !slices.Equal(got, want) {
			t.Errorf("parentNames(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSharedSuffixDMARCIsNotInherited(t *testing.T) {
	// co.za publishes its own DMARC record. It does not belong to
	// example.co.za, so it must not be reported as that domain's policy.
	z := goodZone("example.co.za")
	z.remove("_dmarc.example.co.za", dnsmessage.TypeTXT)
	z.add("_dmarc.co.za", rrTXT("v=DMARC1; p=reject"))
	rep := check(t, "example.co.za", z)
	wantFinding(t, rep, "dmarc_missing", SevProblem)
	if rep.Spoofing.Answer != "Yes" {
		t.Errorf("spoofing = %+v, want Yes", rep.Spoofing)
	}
}

// brokenDNSSEC answers SERVFAIL for everything but DS, which the parent zone
// serves, the way validating resolvers answer for a zone with broken DNSSEC.
func brokenDNSSEC(z *zone) *zone {
	z.servfail = func(name string, qt dnsmessage.Type) bool { return qt != typeDS }
	return z
}

func TestDNSSECBroken(t *testing.T) {
	d := "signed.test"
	rep := check(t, d, brokenDNSSEC(goodZone(d)), brokenDNSSEC(goodZone(d)))
	f := wantFinding(t, rep, "dnssec_broken", SevProblem, "DNSSEC looks broken", "SERVFAIL")
	if !strings.Contains(f.Fix, "DS record") {
		t.Errorf("fix = %q", f.Fix)
	}
	for _, code := range []string{"dnssec_on", "resolvers_agree"} {
		if findCode(rep, code) != nil {
			t.Errorf("%s reported while DNSSEC is broken:\n%s", code, dumpFindings(rep))
		}
	}
	wantFinding(t, rep, "single_resolver", SevNote, "No resolver answered most")
	if rep.Spoofing.Answer != "Not sure" || !strings.Contains(rep.Spoofing.Reason, "DNSSEC") {
		t.Errorf("spoofing = %+v", rep.Spoofing)
	}
	if len(rep.TopFixes) == 0 || !strings.Contains(rep.TopFixes[0], "DS record") {
		t.Errorf("top fixes = %q, want the DNSSEC fix first", rep.TopFixes)
	}
	for _, f := range rep.Findings {
		if f.Code == "lookup_failed" && strings.Contains(f.Message, "no resolver answered") {
			t.Errorf("lookup_failed says no resolver answered, but they answered with an error: %q", f.Message)
		}
		if f.Code == "resolver_partial" && strings.Contains(f.Message, "another resolver") {
			t.Errorf("resolver_partial claims other answers were used: %q", f.Message)
		}
	}
	if !strings.Contains(findCode(rep, "lookup_failed").Message, "SERVFAIL") {
		t.Errorf("lookup_failed should give the error: %q", findCode(rep, "lookup_failed").Message)
	}

	// One healthy resolver and two validating ones that refuse: still broken
	// for most people.
	rep = check(t, d, goodZone(d), brokenDNSSEC(goodZone(d)), brokenDNSSEC(goodZone(d)))
	wantFinding(t, rep, "dnssec_broken", SevProblem)
	if findCode(rep, "dnssec_on") != nil {
		t.Errorf("dnssec_on reported while DNSSEC is broken:\n%s", dumpFindings(rep))
	}
	f = wantFinding(t, rep, "resolver_partial", SevNote, "another resolver")
	_ = f

	// Two healthy, one refusing: a warning.
	rep = check(t, d, goodZone(d), goodZone(d), brokenDNSSEC(goodZone(d)))
	wantFinding(t, rep, "dnssec_broken", SevWarning, "may be broken")
}

func TestZoneServfailWithoutDNSSEC(t *testing.T) {
	// One resolver fails every lookup inside the zone but still gets the
	// (empty) DS answer from the parent: the zone is the problem.
	d := "flaky.test"
	z := goodZone(d)
	z.remove(d, typeDS)
	bad := goodZone(d)
	bad.remove(d, typeDS)
	bad.servfail = func(_ string, qt dnsmessage.Type) bool { return qt != typeDS }
	rep := check(t, d, z, bad)
	wantFinding(t, rep, "zone_servfail", SevWarning, "SERVFAIL")
	if findCode(rep, "dnssec_broken") != nil {
		t.Error("dnssec_broken reported for an unsigned domain")
	}

	// A resolver that fails everything, DS included, may just be broken
	// itself, so the domain is not blamed.
	dead := goodZone(d)
	dead.servfail = func(string, dnsmessage.Type) bool { return true }
	rep = check(t, d, z, dead)
	if findCode(rep, "zone_servfail") != nil || findCode(rep, "dnssec_broken") != nil {
		t.Errorf("domain blamed for a resolver that fails everything:\n%s", dumpFindings(rep))
	}
	wantFinding(t, rep, "resolver_unreachable", SevNote, "SERVFAIL")
}

func TestCoreLookupFailureIsAWarning(t *testing.T) {
	// The TXT answer is too big for UDP and TCP is blocked, so SPF cannot be
	// read anywhere. The report must not exit 0 with "Nothing urgent".
	d := "trunc.test"
	z := goodZone(d)
	z.truncate[d] = true
	z.noTCP = true
	rep := check(t, d, z)
	if rep.Worst() < SevWarning {
		t.Errorf("worst = %v, want at least a warning:\n%s", rep.Worst(), dumpFindings(rep))
	}
	var txt *Finding
	for i, f := range rep.Findings {
		if f.Code == "lookup_failed" && strings.Contains(f.Message, "SPF") {
			txt = &rep.Findings[i]
		}
	}
	if txt == nil || txt.Severity != SevWarning || txt.Fix == "" {
		t.Fatalf("TXT lookup_failed = %+v, want a warning with a fix", txt)
	}
	if !strings.Contains(txt.Message, "TCP retry failed (connection") || strings.Contains(txt.Message, "127.0.0.1") {
		t.Errorf("lookup_failed should explain the TCP failure plainly: %q", txt.Message)
	}
	if rep.Spoofing.Answer != "Not sure" || len(rep.TopFixes) == 0 {
		t.Errorf("spoofing = %+v, top fixes = %q", rep.Spoofing, rep.TopFixes)
	}
}

func TestDomainNotSeenByEveryResolver(t *testing.T) {
	d := "new.test"
	stale := newZone() // knows nothing about new.test yet
	s1, s2 := startFakeDNS(t, stale), startFakeDNS(t, goodZone(d))
	for _, rs := range [][]Resolver{
		{s1.resolver(), s2.resolver()},
		{s1.resolver(), startFakeDNS(t, stale).resolver(), s2.resolver()},
		{s2.resolver(), s1.resolver()},
	} {
		rep, err := checkDomain(context.Background(), NewClient(2*time.Second, 8), rs, d, checkConfig{Selectors: defaultSelectors, Concurrency: 8})
		if err != nil {
			t.Fatal(err)
		}
		if findCode(rep, "domain_not_found") != nil {
			t.Errorf("domain_not_found reported while %s sees the domain:\n%s", s2.addr, dumpFindings(rep))
		}
		f := wantFinding(t, rep, "domain_not_everywhere", SevWarning, s1.addr, s2.addr, "still spreading")
		if !strings.Contains(f.Message, "but "+s2.addr+" does") {
			t.Errorf("message should say who sees it: %q", f.Message)
		}
		// The rest of the report comes from the resolver that sees the domain.
		wantFinding(t, rep, "dmarc_reject", SevOK)
		if rep.Spoofing.Answer != "Unlikely" {
			t.Errorf("spoofing = %+v", rep.Spoofing)
		}
		if findCode(rep, "resolvers_disagree") != nil || findCode(rep, "resolver_unreachable") != nil {
			t.Errorf("the unseen resolver should be explained once, not per record:\n%s", dumpFindings(rep))
		}
		if len(rep.NotSeenBy) != len(rs)-1 {
			t.Errorf("not seen by %q", rep.NotSeenBy)
		}
	}
}

func TestSOASerialOnlyDifferenceIsIgnored(t *testing.T) {
	d := "serial.test"
	newer := goodZone(d)
	newer.remove(d, dnsmessage.TypeSOA).add(d, rrSOA("ns1."+d, 2026111302))
	rep := check(t, d, goodZone(d), newer)
	if rep.Worst() != SevOK {
		t.Errorf("worst = %v, want ok:\n%s", rep.Worst(), dumpFindings(rep))
	}
	wantFinding(t, rep, "resolvers_agree", SevOK, "Both resolvers gave the same answers.")

	// A different primary name server is a real difference.
	moved := goodZone(d)
	moved.remove(d, dnsmessage.TypeSOA).add(d, rrSOA("ns1.newhost.test", 1))
	rep = check(t, d, goodZone(d), moved)
	wantFinding(t, rep, "resolvers_disagree", SevWarning, "zone details (SOA)")
}

func TestResolverHealthIsSharedAcrossDomains(t *testing.T) {
	srv := startFakeDNS(t, goodZone("good.test").add("other.test", rrA("192.0.2.1")))
	dead := Resolver{Name: "Dead resolver", Addrs: []string{closedAddr(t)}}
	c := NewClient(300*time.Millisecond, 8)
	cfg := checkConfig{Selectors: defaultSelectors, Concurrency: 8}
	if _, err := checkDomain(context.Background(), c, []Resolver{dead, srv.resolver()}, "good.test", cfg); err != nil {
		t.Fatal(err)
	}
	rep, err := checkDomain(context.Background(), c, []Resolver{dead, srv.resolver()}, "other.test", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st := rep.Resolvers[0]; st.Usable || st.Error != errSkipped.Error() {
		t.Errorf("dead resolver on the second domain = %+v, want every lookup skipped", st)
	}
}

func TestCNAMEChainKeepsItsOrder(t *testing.T) {
	q := Query{ID: "www", Name: "www.example.com", Type: dnsmessage.TypeA, KeepCNAME: true}
	resp := &Response{Answers: []Answer{
		{Name: "example.com.edgekey.net", Type: "CNAME", Value: "e1234.a.akamaiedge.net", TTL: 20},
		{Name: "e1234.a.akamaiedge.net", Type: "A", Value: "192.0.2.9", TTL: 20},
		{Name: "www.example.com", Type: "CNAME", Value: "example.com.edgekey.net", TTL: 300},
		{Name: "e1234.a.akamaiedge.net", Type: "A", Value: "192.0.2.8", TTL: 20},
	}}
	got := toLookup(q, resp).Values
	want := []string{"CNAME example.com.edgekey.net", "CNAME e1234.a.akamaiedge.net", "A 192.0.2.8", "A 192.0.2.9"}
	if !slices.Equal(got, want) {
		t.Errorf("values = %q, want %q", got, want)
	}
	rep := &Report{Domain: "example.com", Records: []RecordReport{
		{ID: "a", Answered: true, Values: []string{"192.0.2.1"}},
		{ID: "aaaa", Answered: true, Values: []string{}},
		{ID: "www", Answered: true, Values: got},
	}}
	(&analyzer{rep: rep}).website()
	wantFinding(t, rep, "www_ok", SevOK, "example.com.edgekey.net then e1234.a.akamaiedge.net")
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
