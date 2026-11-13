package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Severity says how much a finding matters.
type Severity int

const (
	SevOK Severity = iota
	SevNote
	SevWarning
	SevProblem
)

func (s Severity) String() string {
	switch s {
	case SevOK:
		return "ok"
	case SevNote:
		return "note"
	case SevWarning:
		return "warning"
	case SevProblem:
		return "problem"
	}
	return "unknown"
}

// MarshalText makes severities show up as words in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText reads a severity word back, so the JSON output round-trips.
func (s *Severity) UnmarshalText(b []byte) error {
	for _, v := range []Severity{SevOK, SevNote, SevWarning, SevProblem} {
		if string(b) == v.String() {
			*s = v
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", b)
}

// Report areas, in the order the text report shows them.
const (
	areaDomain    = "Domain"
	areaWebsite   = "Website"
	areaNS        = "Name servers"
	areaMail      = "Email delivery"
	areaMailSec   = "Email security"
	areaDomainSec = "Domain security"
	areaResolvers = "Resolvers"
)

var areaOrder = []string{areaDomain, areaWebsite, areaNS, areaMail, areaMailSec, areaDomainSec, areaResolvers}

// Finding is one thing the check noticed, in plain words.
type Finding struct {
	Severity Severity `json:"severity"`
	Area     string   `json:"area"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// Verdict answers "Could someone send email that looks like it comes from
// this domain?"
type Verdict struct {
	Answer string `json:"answer"` // Yes, Partly, Unlikely, or Not sure
	Reason string `json:"reason"`
}

// ResolverStatus says how one resolver did.
type ResolverStatus struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Usable    bool     `json:"usable"`
	Lookups   int      `json:"lookups"`
	Failed    int      `json:"failed"`
	Error     string   `json:"error,omitempty"`
}

// ResolverAnswer is one resolver's answer for one record.
type ResolverAnswer struct {
	Resolver string   `json:"resolver"`
	Values   []string `json:"values"`
	NotFound bool     `json:"nxdomain,omitempty"`
	UsedTCP  bool     `json:"used_tcp,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// RecordReport is one record lookup across all resolvers.
type RecordReport struct {
	ID          string           `json:"id"`
	Label       string           `json:"label"`
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Values      []string         `json:"values"` // the answer most resolvers gave
	Answered    bool             `json:"answered"`
	NotFound    bool             `json:"nxdomain"`
	Agree       bool             `json:"resolvers_agree"`
	TTL         uint32           `json:"max_ttl"`
	PerResolver []ResolverAnswer `json:"per_resolver"`
}

// SPFSummary is the SPF part of the report.
type SPFSummary struct {
	Record          string   `json:"record"`
	All             string   `json:"all"`
	Lookups         int      `json:"dns_lookups"`
	LookupsComplete bool     `json:"dns_lookups_complete"`
	MissingIncludes []string `json:"includes_without_spf,omitempty"`
}

// DMARCSummary is the DMARC part of the report.
type DMARCSummary struct {
	Record          string   `json:"record"`
	Policy          string   `json:"policy"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Pct             int      `json:"pct"`
	Reports         []string `json:"rua"`
}

// Report is everything found for one domain.
type Report struct {
	Domain        string           `json:"domain"`
	CheckedAt     time.Time        `json:"checked_at"`
	Resolvers     []ResolverStatus `json:"resolvers"`
	Records       []RecordReport   `json:"records"`
	SPF           *SPFSummary      `json:"spf"`
	DMARC         *DMARCSummary    `json:"dmarc"`
	DKIMSelectors []string         `json:"dkim_selectors_found"`
	DNSSEC        bool             `json:"dnssec_signed"`
	Findings      []Finding        `json:"findings"`
	Spoofing      Verdict          `json:"spoofing"`
	TopFixes      []string         `json:"top_fixes"`
	OptionalFixes []string         `json:"optional_fixes"`
}

// Worst returns the most serious severity in the report.
func (r *Report) Worst() Severity {
	w := SevOK
	for _, f := range r.Findings {
		w = max(w, f.Severity)
	}
	return w
}

// record returns the record with the given ID, or an empty one.
func (r *Report) record(id string) *RecordReport {
	for i := range r.Records {
		if r.Records[i].ID == id {
			return &r.Records[i]
		}
	}
	return &RecordReport{ID: id, Values: []string{}}
}

// answerGroup is a set of resolvers that gave the same answer.
type answerGroup struct {
	Values    []string
	Resolvers []string
	NX        int
}

// answerGroups groups resolvers by answer, skipping resolvers that failed.
// Groups come out in the order their first resolver appears.
func answerGroups(per []ResolverAnswer) []answerGroup {
	var gs []answerGroup
	for _, ra := range per {
		if ra.Error != "" {
			continue
		}
		key := joinValues(ra.Values)
		i := slices.IndexFunc(gs, func(g answerGroup) bool { return joinValues(g.Values) == key })
		if i < 0 {
			gs = append(gs, answerGroup{Values: ra.Values})
			i = len(gs) - 1
		}
		gs[i].Resolvers = append(gs[i].Resolvers, ra.Resolver)
		if ra.NotFound {
			gs[i].NX++
		}
	}
	return gs
}

// buildRecords turns raw results into per-record reports. The main answer is
// the one most resolvers gave; on a tie, the earlier resolver wins.
func buildRecords(resolvers []Resolver, results []QueryResult) []RecordReport {
	out := make([]RecordReport, 0, len(results))
	for _, qr := range results {
		rr := RecordReport{ID: qr.ID, Label: qr.Label, Name: qr.Name, Type: typeName(qr.Type), Values: []string{}}
		if qr.KeepCNAME {
			rr.Type = "CNAME/" + rr.Type
		}
		for ri, l := range qr.Lookups {
			ra := ResolverAnswer{Resolver: resolvers[ri].Name, Values: l.Values, NotFound: l.NXDomain, UsedTCP: l.UsedTCP}
			if ra.Values == nil {
				ra.Values = []string{}
			}
			if l.Err != nil {
				ra.Error = plainError(l.Err)
			} else {
				rr.Answered = true
				rr.TTL = max(rr.TTL, l.TTL)
			}
			rr.PerResolver = append(rr.PerResolver, ra)
		}
		groups := answerGroups(rr.PerResolver)
		best := -1
		for i, g := range groups {
			if best < 0 || len(g.Resolvers) > len(groups[best].Resolvers) {
				best = i
			}
		}
		if best >= 0 {
			rr.Values = groups[best].Values
			rr.NotFound = len(rr.Values) == 0 && groups[best].NX*2 > len(groups[best].Resolvers)
		}
		rr.Agree = len(groups) <= 1
		out = append(out, rr)
	}
	return out
}

// resolverStatuses works out which resolvers answered at all.
func resolverStatuses(resolvers []Resolver, results []QueryResult) ([]ResolverStatus, []int) {
	statuses := make([]ResolverStatus, len(resolvers))
	var usable []int
	for ri, r := range resolvers {
		st := ResolverStatus{Name: r.Name, Addresses: r.Addrs}
		for _, qr := range results {
			l := qr.Lookups[ri]
			st.Lookups++
			if l.Err == nil {
				st.Usable = true
				continue
			}
			st.Failed++
			if st.Error == "" || st.Error == errSkipped.Error() {
				st.Error = plainError(l.Err)
			}
		}
		if st.Usable {
			usable = append(usable, ri)
		}
		statuses[ri] = st
	}
	return statuses, usable
}

// fixRank orders fixes: lower comes first among findings of equal severity.
var fixRank = map[string]int{
	"domain_not_found":     0,
	"spf_plus_all":         1,
	"spf_multiple":         2,
	"dmarc_multiple":       3,
	"dmarc_invalid":        3,
	"spf_missing":          4,
	"dmarc_missing":        5,
	"spf_too_many_lookups": 6,
	"spf_syntax":           7,
	"dmarc_none":           10,
	"spf_neutral_all":      11,
	"spf_no_all":           12,
	"spf_include_missing":  13,
	"no_mx":                14,
	"apex_no_address":      15,
	"www_missing":          16,
	"www_dangling":         16,
	"resolvers_disagree":   17,
	"dmarc_pct":            18,
	"dmarc_sp_none":        19,
	"ns_single":            20,
	"dmarc_no_rua":         30,
	"dkim_none_found":      31,
	"spf_softfail":         32,
	"caa_missing":          33,
	"dnssec_off":           34,
	"mta_sts_missing":      35,
	"tls_rpt_missing":      36,
	"spf_ptr":              37,
	"bimi_missing":         38,
}

func rankOf(code string) int {
	if r, ok := fixRank[code]; ok {
		return r
	}
	return 99
}

const (
	maxTopFixes      = 5
	maxOptionalFixes = 3
)

// topFixes lists fixes for warnings and problems, most urgent first. When
// there are none, optional lists up to three fixes from notes instead.
func topFixes(findings []Finding) (top, optional []string) {
	sorted := slices.Clone(findings)
	slices.SortStableFunc(sorted, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return int(b.Severity) - int(a.Severity)
		}
		return rankOf(a.Code) - rankOf(b.Code)
	})
	seen := map[string]bool{}
	for _, f := range sorted {
		if f.Fix == "" || seen[f.Code] {
			continue
		}
		seen[f.Code] = true
		switch {
		case f.Severity >= SevWarning && len(top) < maxTopFixes:
			top = append(top, f.Fix)
		case f.Severity == SevNote && len(optional) < maxOptionalFixes:
			optional = append(optional, f.Fix)
		}
	}
	if len(top) > 0 {
		optional = nil
	}
	if top == nil {
		top = []string{}
	}
	if optional == nil {
		optional = []string{}
	}
	return top, optional
}

// spfState sums up SPF for the spoofing verdict.
type spfState int

const (
	spfUnknown spfState = iota
	spfMissing
	spfBroken
	spfPlusAll
	spfNeutral
	spfSoft
	spfHard
	spfRedirect
)

// dmarcState sums up DMARC for the spoofing verdict.
type dmarcState struct {
	known   bool
	present bool
	policy  string // "" when missing or not valid
	pct     int
}

type analyzer struct {
	rep *Report
}

func (a *analyzer) add(sev Severity, area, code, msg, fix string) {
	a.rep.Findings = append(a.rep.Findings, Finding{Severity: sev, Area: area, Code: code, Message: msg, Fix: fix})
}

// unknown adds a note and returns true when no resolver could answer.
func (a *analyzer) unknown(r *RecordReport, area string) bool {
	if r.Answered {
		return false
	}
	a.add(SevNote, area, "lookup_failed", fmt.Sprintf("Could not look up the %s for %s, because no resolver answered.", r.Label, r.Name), "")
	return true
}

// analyze turns the records into findings, the spoofing verdict and fixes.
func analyze(rep *Report, exp *spfExpansion) {
	a := &analyzer{rep: rep}
	a.resolvers()
	if soa := rep.record("soa"); soa.Answered && soa.NotFound {
		a.add(SevProblem, areaDomain, "domain_not_found",
			fmt.Sprintf("%s was not found in DNS. It may be misspelled, expired, or not registered.", rep.Domain),
			"Check the spelling. If this is your domain, check with your registrar that it is registered, paid up, and pointed at your DNS provider.")
		rep.Spoofing = Verdict{Answer: "Not sure", Reason: "the domain was not found in DNS, so there is nothing to check."}
		rep.TopFixes, rep.OptionalFixes = topFixes(rep.Findings)
		return
	}
	a.website()
	a.nameServers()
	hasMail := a.mail()
	spf := a.spf(exp, hasMail)
	dmarc := a.dmarc()
	a.dkim()
	a.mailExtras(hasMail, dmarc)
	a.domainSecurity()
	a.disagreements()
	rep.Spoofing = spoofVerdict(rep.Domain, spf, dmarc)
	rep.TopFixes, rep.OptionalFixes = topFixes(rep.Findings)
}

func (a *analyzer) resolvers() {
	for _, st := range a.rep.Resolvers {
		switch {
		case !st.Usable:
			a.add(SevNote, areaResolvers, "resolver_unreachable",
				fmt.Sprintf("Could not use %s: %s. The check carried on with the other resolvers.", st.Name, st.Error), "")
		case st.Failed > 0:
			a.add(SevNote, areaResolvers, "resolver_partial",
				fmt.Sprintf("%s did not answer %d of %d lookups (%s). Answers from the other resolvers were used for those.", st.Name, st.Failed, st.Lookups, st.Error), "")
		}
	}
}

func (a *analyzer) website() {
	d := a.rep.Domain
	v4, v6, www := a.rep.record("a"), a.rep.record("aaaa"), a.rep.record("www")
	if !a.unknown(v4, areaWebsite) && !a.unknown(v6, areaWebsite) {
		switch {
		case len(v4.Values) > 0 && len(v6.Values) > 0:
			a.add(SevOK, areaWebsite, "apex_ok", fmt.Sprintf("%s points to %s, and to %s over IPv6.", d, listShort(v4.Values, 3), listShort(v6.Values, 2)), "")
		case len(v4.Values) > 0:
			a.add(SevOK, areaWebsite, "apex_ok", fmt.Sprintf("%s points to %s.", d, listShort(v4.Values, 3)), "")
			a.add(SevNote, areaWebsite, "ipv6_missing", fmt.Sprintf("%s has no IPv6 address (AAAA record). That is common and fine for now.", d), "")
		case len(v6.Values) > 0:
			a.add(SevOK, areaWebsite, "apex_ok", fmt.Sprintf("%s points to %s (IPv6 only).", d, listShort(v6.Values, 2)), "")
		default:
			a.add(SevWarning, areaWebsite, "apex_no_address",
				fmt.Sprintf("%s does not point to any server, so typing it into a browser without www will not load a website.", d),
				fmt.Sprintf("Point %s itself at your website (an A record, or an ALIAS or flattened CNAME if your DNS provider offers one), or redirect it to www.", d))
		}
	}
	if a.unknown(www, areaWebsite) {
		return
	}
	var cnames, addrs []string
	for _, v := range www.Values {
		if t, ok := strings.CutPrefix(v, "CNAME "); ok {
			cnames = append(cnames, t)
		} else if t, ok := strings.CutPrefix(v, "A "); ok {
			addrs = append(addrs, t)
		}
	}
	switch {
	case len(cnames) > 0 && len(addrs) == 0:
		a.add(SevWarning, areaWebsite, "www_dangling",
			fmt.Sprintf("www.%s points to %s, but that name has no address, so www does not load.", d, strings.Join(cnames, " then ")),
			fmt.Sprintf("Point www.%s at your current website host, or remove the old www record.", d))
	case len(cnames) > 0:
		a.add(SevOK, areaWebsite, "www_ok", fmt.Sprintf("www.%s works. It points to %s.", d, strings.Join(cnames, " then ")), "")
	case len(addrs) > 0:
		a.add(SevOK, areaWebsite, "www_ok", fmt.Sprintf("www.%s works. It points to %s.", d, listShort(addrs, 3)), "")
	default:
		a.add(SevWarning, areaWebsite, "www_missing",
			fmt.Sprintf("www.%s does not exist, so anyone who types www in front of your domain gets an error.", d),
			fmt.Sprintf("Add a www record (usually a CNAME to your website host) so www.%s works too.", d))
	}
}

func (a *analyzer) nameServers() {
	ns := a.rep.record("ns")
	if a.unknown(ns, areaNS) {
		return
	}
	hint := ""
	if p := guessProvider(ns.Values, nsProviders); p != "" {
		hint = " (looks like " + p + ")"
	}
	switch n := len(ns.Values); {
	case n == 0:
		a.add(SevNote, areaNS, "ns_none",
			fmt.Sprintf("No name servers are listed for %s itself. That is normal for a subdomain, which uses its parent domain's name servers.", a.rep.Domain), "")
	case n == 1:
		a.add(SevWarning, areaNS, "ns_single",
			fmt.Sprintf("Only one name server: %s%s. If it goes down, the whole domain stops working.", ns.Values[0], hint),
			"Use at least two name servers, so the domain keeps working if one of them goes down.")
	default:
		a.add(SevOK, areaNS, "ns_ok", fmt.Sprintf("%d name servers: %s%s.", n, listShort(ns.Values, 4), hint), "")
	}
}

// mail reports on MX records and returns whether the domain receives email.
func (a *analyzer) mail() bool {
	d := a.rep.Domain
	mx := a.rep.record("mx")
	if a.unknown(mx, areaMail) {
		return false
	}
	type mxHost struct {
		pref int
		host string
	}
	var hosts []mxHost
	for _, v := range mx.Values {
		p, h, _ := strings.Cut(v, " ")
		n, _ := strconv.Atoi(p)
		hosts = append(hosts, mxHost{n, h})
	}
	slices.SortStableFunc(hosts, func(x, y mxHost) int { return x.pref - y.pref })
	switch {
	case len(hosts) == 0:
		a.add(SevWarning, areaMail, "no_mx",
			fmt.Sprintf("%s has no MX records, so email sent to addresses at %s has nowhere to go.", d, d),
			fmt.Sprintf("If people should be able to email you at %s, add the MX records your email provider gives you. If the domain never receives email, add a null MX record (priority 0, host \".\") so senders get a clear answer.", d))
		return false
	case len(hosts) == 1 && hosts[0].host == ".":
		a.add(SevOK, areaMail, "mx_null", fmt.Sprintf("%s says it does not accept email (a null MX record). That is right if the domain never receives email.", d), "")
		return false
	}
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.host
	}
	hint := ""
	if p := guessProvider(names, mxProviders); p != "" {
		hint = " This looks like " + p + "."
	}
	a.add(SevOK, areaMail, "mx_ok", fmt.Sprintf("Email for %s is delivered to %s.%s", d, listShort(names, 4), hint), "")
	return true
}

func (a *analyzer) spf(exp *spfExpansion, hasMail bool) spfState {
	d := a.rep.Domain
	txt := a.rep.record("txt")
	if a.unknown(txt, areaMailSec) {
		return spfUnknown
	}
	var records []string
	for _, v := range txt.Values {
		if isSPF(v) {
			records = append(records, v)
		}
	}
	switch len(records) {
	case 0:
		fix := fmt.Sprintf("Add one TXT record at %s that lists the services allowed to send your email and ends in -all. Your email provider's setup guide gives the exact line.", d)
		if !hasMail {
			fix += " If the domain never sends email, use \"v=spf1 -all\"."
		}
		a.add(SevProblem, areaMailSec, "spf_missing",
			fmt.Sprintf("No SPF record. SPF is the list of servers allowed to send email for %s. Without it, receivers cannot tell your real email from fakes.", d), fix)
		return spfMissing
	case 1:
	default:
		a.add(SevProblem, areaMailSec, "spf_multiple",
			fmt.Sprintf("There are %d SPF records. Only one is allowed, so receivers treat SPF as broken for all email from %s.", len(records), d),
			"Merge the SPF records into one TXT record that starts with v=spf1 and ends with a single all rule, then delete the extra ones.")
		return spfBroken
	}

	rec := parseSPF(records[0])
	sum := &SPFSummary{Record: rec.Raw, All: rec.All, Lookups: rec.Lookups, LookupsComplete: !rec.Macro}
	if exp != nil {
		sum.Lookups, sum.LookupsComplete, sum.MissingIncludes = exp.Lookups, exp.Complete, exp.Missing
	}
	a.rep.SPF = sum
	state := spfHard
	if len(rec.Unknown) > 0 {
		a.add(SevWarning, areaMailSec, "spf_syntax",
			fmt.Sprintf("The SPF record has something receivers do not understand (%s), so they may treat SPF as broken.", short(strings.Join(rec.Unknown, " "), 60)),
			"Fix or remove the parts of the SPF record that are not valid SPF terms.")
		state = spfBroken
	}
	lookups := fmt.Sprintf("%d", sum.Lookups)
	if !sum.LookupsComplete {
		lookups = "at least " + lookups
	}
	uses := ""
	if sum.Lookups <= 10 {
		uses = fmt.Sprintf(" It uses %s of the 10 allowed DNS lookups.", lookups)
	}
	shown := short(rec.Raw, 120)
	switch rec.All {
	case "+":
		a.add(SevProblem, areaMailSec, "spf_plus_all",
			fmt.Sprintf("The SPF record ends in +all, which approves every server on the internet to send email as %s: %s", d, shown),
			"Change +all at the end of the SPF record to -all (or ~all while you confirm every service that sends your email is listed).")
		state = spfPlusAll
	case "?":
		a.add(SevWarning, areaMailSec, "spf_neutral_all",
			fmt.Sprintf("The SPF record ends in ?all (neutral), which tells receivers nothing about email from other servers: %s", shown),
			"Change ?all at the end of the SPF record to -all (or ~all while you confirm every service that sends your email is listed).")
		if state != spfBroken {
			state = spfNeutral
		}
	case "~":
		a.add(SevNote, areaMailSec, "spf_softfail",
			fmt.Sprintf("SPF is set up and ends in ~all (soft fail), so email from servers not on the list is marked as suspicious but not rejected. That works well with an enforcing DMARC policy; -all is the strictest setting.%s Record: %s", uses, shown),
			"Optional: once you are sure every service that sends your email is listed, change ~all to -all.")
		if state != spfBroken {
			state = spfSoft
		}
	case "-":
		a.add(SevOK, areaMailSec, "spf_ok",
			fmt.Sprintf("SPF is set up and ends in -all, so email from servers not on the list should be rejected.%s Record: %s", uses, shown), "")
	default:
		if rec.Redirect != "" {
			a.add(SevOK, areaMailSec, "spf_redirect",
				fmt.Sprintf("SPF is set up and hands over to the record at %s (redirect).%s Record: %s", rec.Redirect, uses, shown), "")
			if state != spfBroken {
				state = spfRedirect
			}
		} else {
			a.add(SevWarning, areaMailSec, "spf_no_all",
				fmt.Sprintf("The SPF record does not end with an all rule, so email from other servers gets a neutral result: %s", shown),
				"Add -all (or ~all while you test) to the end of the SPF record.")
			if state != spfBroken {
				state = spfNeutral
			}
		}
	}
	if sum.Lookups > 10 {
		a.add(SevProblem, areaMailSec, "spf_too_many_lookups",
			fmt.Sprintf("The SPF record needs %s DNS lookups, counting the records it includes. The limit is 10, so receivers may stop checking and treat SPF as broken.", lookups),
			"Remove services you no longer use from the SPF record, or replace include: entries with the ip4: and ip6: addresses they cover, so the record needs 10 lookups or fewer.")
	}
	if exp != nil {
		for _, m := range exp.Missing {
			a.add(SevWarning, areaMailSec, "spf_include_missing",
				fmt.Sprintf("The SPF record includes %s, but %s has no SPF record. Receivers treat that as an error.", m, m),
				fmt.Sprintf("Remove include:%s from the SPF record, or replace it with the include your provider currently documents.", m))
		}
		for _, m := range exp.Multiple {
			a.add(SevWarning, areaMailSec, "spf_include_missing",
				fmt.Sprintf("The SPF record includes %s, which has more than one SPF record. Receivers treat that as an error.", m),
				fmt.Sprintf("Ask the owner of %s to fix their SPF record, or replace the include with their sending addresses.", m))
		}
	}
	if rec.HasPTR {
		a.add(SevNote, areaMailSec, "spf_ptr", "The SPF record uses ptr, which is slow and discouraged. Some receivers ignore it.",
			"Optional: replace ptr in the SPF record with ip4:, ip6: or a: terms.")
	}
	return state
}

func (a *analyzer) dmarc() dmarcState {
	d := a.rep.Domain
	r := a.rep.record("dmarc")
	if a.unknown(r, areaMailSec) {
		return dmarcState{}
	}
	var records []string
	for _, v := range r.Values {
		if isDMARC(v) {
			records = append(records, v)
		}
	}
	switch len(records) {
	case 0:
		a.add(SevProblem, areaMailSec, "dmarc_missing",
			"No DMARC policy. DMARC tells receiving mail servers what to do with email that fails the SPF and DKIM checks, and sends you reports. Without it, each receiver decides for itself and fakes often get through.",
			fmt.Sprintf("Add a TXT record at _dmarc.%s. A safe start is \"v=DMARC1; p=none; rua=mailto:you@%s\" (use a mailbox you read) to collect reports, then move to p=quarantine and then p=reject once the reports show only your real senders.", d, d))
		return dmarcState{known: true}
	case 1:
	default:
		a.add(SevProblem, areaMailSec, "dmarc_multiple",
			fmt.Sprintf("There are %d DMARC records at _dmarc.%s. Receivers ignore DMARC when there is more than one.", len(records), d),
			fmt.Sprintf("Keep one DMARC record at _dmarc.%s and delete the others.", d))
		return dmarcState{known: true, present: true}
	}
	rec := parseDMARC(records[0])
	a.rep.DMARC = &DMARCSummary{Record: rec.Raw, Policy: rec.Policy, SubdomainPolicy: rec.SubPolicy, Pct: rec.Pct, Reports: rec.RUA}
	if a.rep.DMARC.Reports == nil {
		a.rep.DMARC.Reports = []string{}
	}
	st := dmarcState{known: true, present: true, policy: rec.Policy, pct: rec.Pct}
	switch rec.Policy {
	case "":
		a.add(SevProblem, areaMailSec, "dmarc_invalid",
			fmt.Sprintf("The DMARC record has no valid policy (p=none, p=quarantine or p=reject), so receivers ignore it: %s", short(rec.Raw, 120)),
			fmt.Sprintf("Fix the DMARC record at _dmarc.%s so it has a policy, for example \"v=DMARC1; p=none; rua=mailto:you@%s\".", d, d))
	case "none":
		fix := "Once the DMARC reports show that all your real email passes, change p=none to p=quarantine, then to p=reject."
		if len(rec.RUA) == 0 {
			fix = "Add rua=mailto:<a mailbox you read> to the DMARC record so you get reports, then, once they show all your real email passes, change p=none to p=quarantine and then p=reject."
		}
		a.add(SevWarning, areaMailSec, "dmarc_none",
			"DMARC is set to p=none, which is monitoring only. Receivers may report fakes to you, but they are still told to deliver them.", fix)
	case "quarantine":
		a.add(SevOK, areaMailSec, "dmarc_quarantine", "DMARC is set to p=quarantine, so email that fails the checks should go to spam.", "")
	case "reject":
		a.add(SevOK, areaMailSec, "dmarc_reject", "DMARC is set to p=reject, so email that fails the checks should be refused.", "")
	}
	enforcing := rec.Policy == "quarantine" || rec.Policy == "reject"
	if enforcing && rec.Pct < 100 {
		a.add(SevWarning, areaMailSec, "dmarc_pct",
			fmt.Sprintf("DMARC applies its policy to only %d%% of failing email (pct=%d). The rest is treated as if the policy were p=none.", rec.Pct, rec.Pct),
			"Remove pct= from the DMARC record (or set it to 100) so the policy covers all email.")
	}
	if enforcing && rec.SubPolicy == "none" {
		a.add(SevWarning, areaMailSec, "dmarc_sp_none",
			fmt.Sprintf("DMARC protects %s but not its subdomains (sp=none), so fakes from made-up addresses like billing.%s are still delivered.", d, d),
			"Remove sp=none from the DMARC record (or set it to quarantine or reject) so made-up subdomains are blocked too.")
	}
	if len(rec.RUA) > 0 {
		a.add(SevOK, areaMailSec, "dmarc_rua", fmt.Sprintf("DMARC reports are sent to %s.", listShort(rec.RUA, 3)), "")
	} else {
		a.add(SevNote, areaMailSec, "dmarc_no_rua",
			"DMARC has no reporting address (rua=), so nobody receives the reports about who sends email using this domain.",
			"Add rua=mailto:<a mailbox you read> to the DMARC record to get daily reports about who sends email using your domain.")
	}
	return st
}

func (a *analyzer) dkim() {
	var found, revoked []string
	tried := 0
	for _, r := range a.rep.Records {
		sel, ok := strings.CutPrefix(r.ID, "dkim:")
		if !ok || !r.Answered {
			continue
		}
		tried++
		k := readDKIM(r.Values)
		switch {
		case k.Revoked:
			revoked = append(revoked, sel)
		case k.Found:
			found = append(found, sel)
		}
	}
	a.rep.DKIMSelectors = found
	if a.rep.DKIMSelectors == nil {
		a.rep.DKIMSelectors = []string{}
	}
	if tried == 0 {
		return
	}
	if len(found) > 0 {
		msg := fmt.Sprintf("A DKIM signing key was found at selector %s.", found[0])
		if len(found) > 1 {
			msg = fmt.Sprintf("DKIM signing keys were found at selectors %s.", joinAnd(found))
		}
		a.add(SevOK, areaMailSec, "dkim_found", msg, "")
	} else {
		a.add(SevNote, areaMailSec, "dkim_none_found",
			fmt.Sprintf("No DKIM key was found at the %d common selector names checked. DKIM may still be set up under a name this check did not try.", tried),
			"Turn on DKIM signing in your email provider (and in any service that sends email for you) and publish the record it gives you. If DKIM is already on, run this check again with -selectors and your selector name.")
	}
	if len(revoked) > 0 {
		a.add(SevNote, areaMailSec, "dkim_revoked",
			fmt.Sprintf("DKIM selector %s has an empty key, which means that key was withdrawn.", joinAnd(revoked)), "")
	}
}

func (a *analyzer) mailExtras(hasMail bool, dmarc dmarcState) {
	d := a.rep.Domain
	has := func(id, version string) bool {
		for _, v := range a.rep.record(id).Values {
			if hasVersion(v, version) {
				return true
			}
		}
		return false
	}
	switch {
	case has("mta-sts", "STSv1"):
		a.add(SevOK, areaMailSec, "mta_sts_ok", "MTA-STS is published, so other mail servers are asked to use encrypted connections when they deliver to you.", "")
	case hasMail && a.rep.record("mta-sts").Answered:
		a.add(SevNote, areaMailSec, "mta_sts_missing",
			"No MTA-STS record. MTA-STS asks other mail servers to always use an encrypted connection when they deliver email to you.",
			fmt.Sprintf("Optional: publish an MTA-STS policy (a TXT record at _mta-sts.%s plus a small policy file on https://mta-sts.%s) so email to you is always encrypted in transit.", d, d))
	}
	switch {
	case has("tls-rpt", "TLSRPTv1"):
		a.add(SevOK, areaMailSec, "tls_rpt_ok", "TLS reporting (TLS-RPT) is set up, so you get reports when encrypted delivery to you fails.", "")
	case hasMail && a.rep.record("tls-rpt").Answered:
		a.add(SevNote, areaMailSec, "tls_rpt_missing",
			"No TLS reporting record (TLS-RPT), so nobody is told when other servers fail to deliver email to you over an encrypted connection.",
			fmt.Sprintf("Optional: add a TXT record at _smtp._tls.%s like \"v=TLSRPTv1; rua=mailto:you@%s\" to get those reports.", d, d))
	}
	enforcing := dmarc.policy == "quarantine" || dmarc.policy == "reject"
	switch {
	case has("bimi", "BIMI1"):
		a.add(SevOK, areaMailSec, "bimi_ok", "A BIMI record is published, so some inboxes can show your logo next to your email.", "")
	case enforcing && a.rep.record("bimi").Answered:
		a.add(SevNote, areaMailSec, "bimi_missing",
			"No BIMI record. With DMARC already enforcing, BIMI lets some inboxes show your logo next to your email.",
			fmt.Sprintf("Optional: publish a BIMI record at default._bimi.%s pointing to your logo in SVG format.", d))
	}
}

func (a *analyzer) domainSecurity() {
	d := a.rep.Domain
	caa := a.rep.record("caa")
	if !a.unknown(caa, areaDomainSec) {
		var issuers []string
		for _, v := range caa.Values {
			// Values look like: 0 issue "letsencrypt.org"
			parts := strings.SplitN(v, " ", 3)
			if len(parts) == 3 && (parts[1] == "issue" || parts[1] == "issuewild") {
				name, _, _ := strings.Cut(strings.Trim(parts[2], `"`), ";")
				if name = strings.TrimSpace(name); name != "" && !slices.Contains(issuers, name) {
					issuers = append(issuers, name)
				}
			}
		}
		switch {
		case len(issuers) > 0:
			a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("CAA limits who may issue certificates for %s to: %s.", d, strings.Join(issuers, ", ")), "")
		case len(caa.Values) > 0:
			a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("CAA records are published for %s.", d), "")
		default:
			a.add(SevNote, areaDomainSec, "caa_missing",
				fmt.Sprintf("No CAA record, so any certificate authority may issue a certificate for %s.", d),
				"Optional: add a CAA record naming the certificate authority you use, for example 0 issue \"letsencrypt.org\" if your certificates come from Let's Encrypt.")
		}
	}
	ds := a.rep.record("ds")
	if a.unknown(ds, areaDomainSec) {
		return
	}
	if len(ds.Values) > 0 {
		a.rep.DNSSEC = true
		a.add(SevOK, areaDomainSec, "dnssec_on", "DNSSEC is on (a DS record is published at the registry), so resolvers can detect forged DNS answers for this domain.", "")
		return
	}
	a.add(SevNote, areaDomainSec, "dnssec_off",
		"DNSSEC is off. DNSSEC lets resolvers detect forged DNS answers for this domain.",
		"Optional: turn on DNSSEC in your DNS provider's settings, then add the DS record it gives you at your domain registrar.")
}

// addressIDs are records where different answers can be normal (CDNs hand out
// different addresses in different places).
var addressIDs = map[string]bool{"a": true, "aaaa": true, "www": true}

func (a *analyzer) disagreements() {
	usable := 0
	for _, st := range a.rep.Resolvers {
		if st.Usable {
			usable++
		}
	}
	disagree := false
	for _, r := range a.rep.Records {
		groups := answerGroups(r.PerResolver)
		if len(groups) < 2 {
			continue
		}
		disagree = true
		someEmpty := slices.ContainsFunc(groups, func(g answerGroup) bool { return len(g.Values) == 0 })
		what := fmt.Sprintf("Resolvers disagree about the %s for %s: %s.", r.Label, r.Name, describeGroups(groups))
		if addressIDs[r.ID] && !someEmpty {
			a.add(SevNote, areaResolvers, "addresses_differ",
				what+" That is normal for sites behind a content delivery network (CDN), which hands out different addresses in different places. If you did not just change this and do not use a CDN, check your DNS settings.", "")
			continue
		}
		a.add(SevWarning, areaResolvers, "resolvers_disagree",
			fmt.Sprintf("%s This usually means a recent change is still spreading. Old answers can stay cached for up to %s.", what, humanDuration(r.TTL)),
			"If you changed DNS records recently, wait for the old answers to expire, then run this check again. If nothing changed, check that all your name servers serve the same records.")
	}
	if disagree {
		return
	}
	if usable > 1 {
		a.add(SevOK, areaResolvers, "resolvers_agree", fmt.Sprintf("All %d resolvers that answered gave the same answers.", usable), "")
	} else {
		a.add(SevNote, areaResolvers, "single_resolver", "Only one resolver answered, so answers could not be compared.", "")
	}
}

// describeGroups says which resolvers saw what, for example:
// "Cloudflare (1.1.1.1) and Google (8.8.8.8) see 10 mx1.example.com; Quad9 (9.9.9.9) sees nothing".
func describeGroups(groups []answerGroup) string {
	parts := make([]string, len(groups))
	for i, g := range groups {
		verb := "see"
		if len(g.Resolvers) == 1 {
			verb = "sees"
		}
		what := "nothing"
		if len(g.Values) > 0 {
			what = short(strings.Join(g.Values, ", "), 100)
		}
		parts[i] = fmt.Sprintf("%s %s %s", joinAnd(g.Resolvers), verb, what)
	}
	return strings.Join(parts, "; ")
}

// spoofVerdict answers whether someone could send email that looks like it
// comes from the domain.
func spoofVerdict(domain string, s spfState, d dmarcState) Verdict {
	if s == spfUnknown || !d.known {
		return Verdict{Answer: "Not sure", Reason: "some lookups failed, so SPF and DMARC could not be fully checked. Run the check again."}
	}
	if s == spfPlusAll {
		return Verdict{Answer: "Yes", Reason: "the SPF record ends in +all, which approves every server on the internet to send email as " + domain + "."}
	}
	switch {
	case d.policy == "reject" && d.pct >= 100:
		return Verdict{Answer: "Unlikely", Reason: "DMARC is set to reject, so receiving mail servers are told to refuse email that fails the SPF and DKIM checks."}
	case d.policy == "quarantine" && d.pct >= 100:
		return Verdict{Answer: "Unlikely", Reason: "DMARC is set to quarantine, so email that fails the SPF and DKIM checks should land in spam instead of the inbox."}
	case d.policy == "reject" || d.policy == "quarantine":
		return Verdict{Answer: "Partly", Reason: fmt.Sprintf("DMARC applies its %s policy to only %d%% of failing email, so the rest is handled as if there were no policy.", d.policy, d.pct)}
	}
	dm := "there is no DMARC policy"
	switch {
	case d.policy == "none":
		dm = "DMARC is set to monitoring only (p=none)"
	case d.present:
		dm = "the DMARC record is not valid"
	}
	switch s {
	case spfHard, spfSoft, spfRedirect:
		return Verdict{Answer: "Partly", Reason: "SPF catches some fakes, but " + dm + ", so nothing stops a fake that shows " + domain + " in the From line people see."}
	}
	sp := "there is no SPF record"
	switch s {
	case spfBroken:
		sp = "the SPF setup is broken"
	case spfNeutral:
		sp = "SPF does not say what to do with other servers"
	}
	return Verdict{Answer: "Yes", Reason: sp + " and " + dm + ", so nothing tells receiving mail servers to block fake email."}
}

// listShort shows up to n items, then "and N more".
func listShort(items []string, n int) string {
	if len(items) <= n {
		return joinAnd(items)
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
}

// joinAnd joins items as "a", "a and b", or "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// short cuts s to at most n characters, adding "..." when it was cut.
func short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

// humanDuration turns a TTL in seconds into plain words.
func humanDuration(sec uint32) string {
	switch {
	case sec < 120:
		return fmt.Sprintf("%d seconds", sec)
	case sec < 2*3600:
		return fmt.Sprintf("%d minutes", sec/60)
	case sec < 2*86400:
		return fmt.Sprintf("%d hours", sec/3600)
	}
	return fmt.Sprintf("%d days", sec/86400)
}
