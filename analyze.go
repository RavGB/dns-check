package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
	servFail bool     // the resolver answered SERVFAIL
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
	FoundAt         string   `json:"found_at"` // where the record is: _dmarc.<domain>, or a parent domain's
	Policy          string   `json:"policy"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	AppliedPolicy   string   `json:"applied_policy"` // the policy that applies to this domain
	Pct             int      `json:"pct"`
	Reports         []string `json:"rua"`
}

// Report is everything found for one domain.
type Report struct {
	Domain        string           `json:"domain"`
	InputNote     string           `json:"input_note,omitempty"` // how the input was changed, for example a www. left off
	CheckedAt     time.Time        `json:"checked_at"`
	NotSeenBy     []string         `json:"not_seen_by,omitempty"` // resolvers that say the domain does not exist, while others see it
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
				var rc *RCodeError
				ra.servFail = errors.As(l.Err, &rc) && rc.RCode == dnsmessage.RCodeServerFailure
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
	"domain_not_found":      0,
	"dnssec_broken":         0,
	"domain_not_everywhere": 0,
	"spf_plus_all":          1,
	"spf_multiple":          2,
	"dmarc_multiple":        3,
	"dmarc_invalid":         3,
	"spf_missing":           4,
	"dmarc_missing":         5,
	"spf_too_many_lookups":  6,
	"spf_syntax":            7,
	"lookup_failed":         8,
	"zone_servfail":         9,
	"dmarc_none":            10,
	"spf_neutral_all":       11,
	"spf_no_all":            12,
	"spf_include_missing":   13,
	"spf_after_all":         13,
	"no_mx":                 14,
	"apex_no_address":       15,
	"www_missing":           16,
	"www_dangling":          16,
	"resolvers_disagree":    17,
	"dmarc_pct":             18,
	"dmarc_sp_none":         19,
	"ns_single":             20,
	"dmarc_no_rua":          30,
	"dkim_none_found":       31,
	"spf_softfail":          32,
	"caa_missing":           33,
	"dnssec_off":            34,
	"mta_sts_missing":       35,
	"tls_rpt_missing":       36,
	"spf_ptr":               37,
	"bimi_missing":          38,
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
	policy  string // the policy that applies; "" when missing or not valid
	tag     string // "p", or "sp" when a parent domain's subdomain policy applies
	pct     int
}

type analyzer struct {
	rep *Report
	// subdomain is true when the name has no name servers of its own, so it
	// lives inside a parent domain's DNS.
	subdomain bool
}

func (a *analyzer) add(sev Severity, area, code, msg, fix string) {
	a.rep.Findings = append(a.rep.Findings, Finding{Severity: sev, Area: area, Code: code, Message: msg, Fix: fix})
}

// coreIDs are the records the main answers depend on. When they cannot be
// looked up at all, the report cannot be trusted, so that is a warning.
var coreIDs = map[string]bool{"soa": true, "ns": true, "mx": true, "txt": true, "dmarc": true}

// unknown adds a finding and returns true when no resolver gave a usable
// answer for the record.
func (a *analyzer) unknown(r *RecordReport, area string) bool {
	if r.Answered {
		return false
	}
	var why []string
	for _, ra := range r.PerResolver {
		if ra.Error != "" && !slices.Contains(why, ra.Error) {
			why = append(why, ra.Error)
		}
	}
	msg := fmt.Sprintf("Could not look up the %s for %s. None of the resolvers gave a usable answer: %s.", r.Label, r.Name, strings.Join(why, "; "))
	if coreIDs[r.ID] || strings.HasPrefix(r.ID, "parent-dmarc:") {
		a.add(SevWarning, area, "lookup_failed", msg,
			"Run the check again in a few minutes. If the same lookups keep failing, ask your DNS provider to check that the domain's name servers are answering.")
	} else {
		a.add(SevNote, area, "lookup_failed", msg, "")
	}
	return true
}

// parents returns the parent-domain lookups of one kind ("parent-dmarc:",
// "parent-caa:" or "parent-ds:"), nearest parent first.
func (a *analyzer) parents(prefix string) []*RecordReport {
	var out []*RecordReport
	for i := range a.rep.Records {
		if strings.HasPrefix(a.rep.Records[i].ID, prefix) {
			out = append(out, &a.rep.Records[i])
		}
	}
	return out
}

// analyze turns the records into findings, the spoofing verdict and fixes.
func analyze(rep *Report, exp *spfExpansion) {
	a := &analyzer{rep: rep}
	a.resolvers()
	a.notSeen()
	soa := rep.record("soa")
	if soa.Answered && soa.NotFound {
		a.add(SevProblem, areaDomain, "domain_not_found",
			fmt.Sprintf("%s was not found in DNS. It may be misspelled, expired, or not registered.", rep.Domain),
			"Check the spelling. If this is your domain, check with your registrar that it is registered, paid up, and pointed at your DNS provider.")
		rep.Spoofing = Verdict{Answer: "Not sure", Reason: "the domain was not found in DNS, so there is nothing to check."}
		rep.TopFixes, rep.OptionalFixes = topFixes(rep.Findings)
		return
	}
	a.unknown(soa, areaDomain)
	ns := rep.record("ns")
	a.subdomain = ns.Answered && !ns.NotFound && len(ns.Values) == 0 && strings.Count(rep.Domain, ".") >= 2
	dnssecBroken := a.zoneHealth()
	a.website()
	a.nameServers()
	hasMail := a.mail()
	spf := a.spf(exp, hasMail)
	dmarc := a.dmarc()
	a.dkim()
	a.mailExtras(hasMail, dmarc)
	a.domainSecurity(dnssecBroken)
	a.disagreements()
	rep.Spoofing = spoofVerdict(rep.Domain, spf, dmarc)
	if dnssecBroken && rep.Spoofing.Answer == "Not sure" {
		rep.Spoofing.Reason = "DNSSEC looks broken, so resolvers refuse to answer for this domain and SPF and DMARC could not be checked. Fix DNSSEC, then run the check again."
	}
	rep.TopFixes, rep.OptionalFixes = topFixes(rep.Findings)
}

func (a *analyzer) resolvers() {
	for ri, st := range a.rep.Resolvers {
		if slices.Contains(a.rep.NotSeenBy, st.Name) {
			continue // notSeen explains these
		}
		switch {
		case !st.Usable:
			a.add(SevNote, areaResolvers, "resolver_unreachable",
				fmt.Sprintf("Could not use %s: %s. The check carried on with the other resolvers.", st.Name, st.Error), "")
		case st.Failed > 0:
			msg := fmt.Sprintf("%s gave no usable answer for %d of %d lookups (%s).", st.Name, st.Failed, st.Lookups, st.Error)
			if a.coveredByOthers(ri) {
				msg += " Where another resolver answered, its answer was used."
			}
			a.add(SevNote, areaResolvers, "resolver_partial", msg, "")
		}
	}
}

// coveredByOthers reports whether another resolver answered at least one of
// the lookups resolver ri failed.
func (a *analyzer) coveredByOthers(ri int) bool {
	for _, r := range a.rep.Records {
		if ri >= len(r.PerResolver) || r.PerResolver[ri].Error == "" {
			continue
		}
		for j, ra := range r.PerResolver {
			if j != ri && ra.Error == "" {
				return true
			}
		}
	}
	return false
}

// notSeen reports resolvers that say the domain does not exist while other
// resolvers see it. Their answers were left out of the report.
func (a *analyzer) notSeen() {
	if len(a.rep.NotSeenBy) == 0 {
		return
	}
	var seenBy []string
	for _, ra := range a.rep.record("soa").PerResolver {
		if ra.Error == "" {
			seenBy = append(seenBy, ra.Resolver)
		}
	}
	d := a.rep.Domain
	not, does := "does not", "does"
	if len(a.rep.NotSeenBy) > 1 {
		not = "do not"
	}
	if len(seenBy) > 1 {
		does = "do"
	}
	a.add(SevWarning, areaDomain, "domain_not_everywhere",
		fmt.Sprintf("%s %s see %s yet, but %s %s. If you registered the domain or moved its DNS recently, the change is probably still spreading. This report uses the answers from the resolvers that see it.",
			joinAnd(a.rep.NotSeenBy), not, d, joinAnd(seenBy), does),
		"If you registered the domain or moved its DNS recently, wait a few hours and run this check again. If nothing changed, check with your registrar that the domain is registered and pointed at your DNS provider.")
}

// zoneHealth looks for resolvers that answer with an error (SERVFAIL) for
// nearly every lookup about the domain while still answering other lookups,
// such as the DS record, which the parent zone serves. For a signed domain
// that almost always means DNSSEC is broken: validating resolvers refuse
// answers they cannot verify. A resolver that fails every lookup is left
// out, because that looks the same as a broken resolver. It returns true
// when DNSSEC looks broken.
func (a *analyzer) zoneHealth() bool {
	d := a.rep.Domain
	soa := a.rep.record("soa")
	var failing []string
	reachable := 0
	for ri, st := range a.rep.Resolvers {
		if !st.Usable {
			continue
		}
		reachable++
		if ri >= len(soa.PerResolver) || !soa.PerResolver[ri].servFail {
			continue
		}
		own, fails := 0, 0
		for _, r := range a.rep.Records {
			if r.ID == "ds" || strings.HasPrefix(r.ID, "parent-") || ri >= len(r.PerResolver) {
				continue
			}
			own++
			if r.PerResolver[ri].servFail {
				fails++
			}
		}
		if fails*2 >= own {
			failing = append(failing, st.Name)
		}
	}
	if len(failing) == 0 {
		return false
	}
	who := joinAnd(failing)
	if signed, _, _ := a.signed(); signed {
		fix := "Check the DNSSEC settings at your DNS provider and the DS record at your domain registrar: they must match. If you moved to a new DNS provider, remove the old DS record at the registrar (or replace it with the new provider's), then run this check again."
		if len(failing)*2 > reachable {
			a.add(SevProblem, areaDomain, "dnssec_broken",
				fmt.Sprintf("DNSSEC looks broken. %s answered with an error (SERVFAIL) for almost every lookup about %s, even though the domain is signed (a DS record is published). Resolvers that check DNSSEC refuse answers they cannot verify, so many people may not be able to reach the website or send email to %s.", who, d, d),
				fix)
		} else {
			a.add(SevWarning, areaDomain, "dnssec_broken",
				fmt.Sprintf("DNSSEC may be broken. %s answered with an error (SERVFAIL) for almost every lookup about %s, while other resolvers answered normally. The domain is signed (a DS record is published), and resolvers that check DNSSEC refuse answers they cannot verify.", who, d),
				fix)
		}
		return true
	}
	a.add(SevWarning, areaDomain, "zone_servfail",
		fmt.Sprintf("%s answered with an error (SERVFAIL) for almost every lookup about %s. The domain's name servers may be failing for some resolvers, and people who use those resolvers may not be able to reach the website or send email to the domain.", who, d),
		"Check with your DNS provider that every name server listed for the domain is working, then run this check again.")
	return false
}

// signed reports whether DNSSEC is on for the domain and the name whose DS
// record shows it. A subdomain without name servers of its own lives in the
// zone of the nearest parent that has name servers, and shares that zone's
// DNSSEC. failed is a parent lookup that failed before the answer was known.
func (a *analyzer) signed() (on bool, at string, failed *RecordReport) {
	if ds := a.rep.record("ds"); len(ds.Values) > 0 {
		return true, a.rep.Domain, nil
	}
	if !a.subdomain {
		return false, "", nil
	}
	for _, p := range parentNames(a.rep.Domain) {
		ns := a.rep.record("parent-ns:" + p)
		if !ns.Answered {
			return false, "", ns
		}
		if len(ns.Values) == 0 {
			continue // not a zone of its own; look further up
		}
		ds := a.rep.record("parent-ds:" + p)
		if !ds.Answered {
			return false, "", ds
		}
		return len(ds.Values) > 0, p, nil
	}
	return false, "", nil
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
		case a.subdomain:
			a.add(SevNote, areaWebsite, "apex_no_address",
				fmt.Sprintf("%s does not point to any server. That is fine if it is not meant to be a website.", d), "")
		default:
			a.add(SevWarning, areaWebsite, "apex_no_address",
				fmt.Sprintf("%s does not point to any server, so typing it into a browser without www will not load a website.", d),
				fmt.Sprintf("Point %s itself at your website (an A record, or an ALIAS or flattened CNAME if your DNS provider offers one), or redirect it to www.", d))
		}
	}
	if a.subdomain {
		return // nobody types www in front of a subdomain
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
		msg := fmt.Sprintf("No name servers are listed for %s itself. That is normal for a subdomain, which uses its parent domain's name servers.", a.rep.Domain)
		if a.subdomain {
			msg += " Where it has no record of its own, this check uses the parent domain's DMARC policy, CAA records and DNSSEC."
		}
		a.add(SevNote, areaNS, "ns_none", msg, "")
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
	// Receivers give SPF a permanent error, which counts as a failed check,
	// when the record has terms they do not understand, needs more than 10
	// lookups, or includes a domain with no SPF record or with more than one
	// (RFC 7208 sections 4.5, 4.6, 4.6.4 and 5.2). A faker's server matches
	// none of the earlier terms, so its check runs into that error too.
	broken := len(rec.Unknown) > 0 || sum.Lookups > 10 ||
		(exp != nil && (len(exp.Missing) > 0 || len(exp.Multiple) > 0))
	state := spfHard
	if broken {
		state = spfBroken
	}
	if len(rec.Unknown) > 0 {
		a.add(SevWarning, areaMailSec, "spf_syntax",
			fmt.Sprintf("The SPF record has something receivers do not understand (%s), so they may treat SPF as broken.", short(strings.Join(rec.Unknown, " "), 60)),
			"Fix or remove the parts of the SPF record that are not valid SPF terms.")
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
	// When SPF is broken, the -all, ~all and redirect findings would be
	// misleading good news, so they are left out.
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
		if !broken {
			state = spfNeutral
		}
	case "~":
		if !broken {
			a.add(SevNote, areaMailSec, "spf_softfail",
				fmt.Sprintf("SPF is set up and ends in ~all (soft fail), so email from servers not on the list is marked as suspicious but not rejected. That works well with an enforcing DMARC policy; -all is the strictest setting.%s Record: %s", uses, shown),
				"Optional: once you are sure every service that sends your email is listed, change ~all to -all.")
			state = spfSoft
		}
	case "-":
		if !broken {
			a.add(SevOK, areaMailSec, "spf_ok",
				fmt.Sprintf("SPF is set up and ends in -all, so email from servers not on the list should be rejected.%s Record: %s", uses, shown), "")
		}
	default:
		if rec.Redirect != "" {
			if !broken {
				a.add(SevOK, areaMailSec, "spf_redirect",
					fmt.Sprintf("SPF is set up and hands over to the record at %s (redirect).%s Record: %s", rec.Redirect, uses, shown), "")
				state = spfRedirect
			}
		} else {
			a.add(SevWarning, areaMailSec, "spf_no_all",
				fmt.Sprintf("The SPF record does not end with an all rule, so email from other servers gets a neutral result: %s", shown),
				"Add -all (or ~all while you test) to the end of the SPF record.")
			if !broken {
				state = spfNeutral
			}
		}
	}
	if len(rec.AfterAll) > 0 {
		after := short(strings.Join(rec.AfterAll, " "), 80)
		a.add(SevWarning, areaMailSec, "spf_after_all",
			fmt.Sprintf("The SPF record has %s after its all rule (%s). Receivers stop reading at the all rule, so anything after it is ignored and the servers listed there are not approved. Record: %s", after, rec.AllTerm, shown),
			fmt.Sprintf("Move %s in front of %s, so the all rule is the last part of the SPF record. This often happens when a new email service is added at the end of the record.", after, rec.AllTerm))
	}
	if sum.Lookups > 10 {
		a.add(SevProblem, areaMailSec, "spf_too_many_lookups",
			fmt.Sprintf("The SPF record needs %s DNS lookups, counting the records it includes. The limit is 10, so receivers treat SPF as broken. Record: %s", lookups, shown),
			"Remove services you no longer use from the SPF record, or replace include: entries with the ip4: and ip6: addresses they cover, so the record needs 10 lookups or fewer.")
	}
	if exp != nil {
		for _, m := range exp.Missing {
			a.add(SevProblem, areaMailSec, "spf_include_missing",
				fmt.Sprintf("The SPF record includes %s, but %s has no SPF record. Receivers treat that as an error, so SPF is broken. Record: %s", m, m, shown),
				fmt.Sprintf("Remove include:%s from the SPF record, or replace it with the include your provider currently documents.", m))
		}
		for _, m := range exp.Multiple {
			a.add(SevProblem, areaMailSec, "spf_include_missing",
				fmt.Sprintf("The SPF record includes %s, which has more than one SPF record. Receivers treat that as an error, so SPF is broken. Record: %s", m, shown),
				fmt.Sprintf("Ask the owner of %s to fix their SPF record, or replace the include with their sending addresses.", m))
		}
	}
	if rec.HasPTR {
		a.add(SevNote, areaMailSec, "spf_ptr", "The SPF record uses ptr, which is slow and discouraged. Some receivers ignore it.",
			"Optional: replace ptr in the SPF record with ip4:, ip6: or a: terms.")
	}
	return state
}

func dmarcRecords(values []string) []string {
	var out []string
	for _, v := range values {
		if isDMARC(v) {
			out = append(out, v)
		}
	}
	return out
}

// dmarc reports on the DMARC policy. When the domain has no DMARC record of
// its own, the nearest parent domain's record applies, using its subdomain
// policy (sp=) when it has one and its main policy (p=) otherwise (RFC 7489
// section 6.6.3).
func (a *analyzer) dmarc() dmarcState {
	d := a.rep.Domain
	r := a.rep.record("dmarc")
	if a.unknown(r, areaMailSec) {
		return dmarcState{}
	}
	records := dmarcRecords(r.Values)
	src, inherited := r, false
	parents := a.parents("parent-dmarc:")
	if len(records) == 0 {
		for _, p := range parents {
			if a.unknown(p, areaMailSec) {
				return dmarcState{}
			}
			if recs := dmarcRecords(p.Values); len(recs) > 0 {
				records, src, inherited = recs, p, true
				break
			}
		}
	}
	switch len(records) {
	case 0:
		msg := "No DMARC policy. DMARC tells receiving mail servers what to do with email that fails the SPF and DKIM checks, and sends you reports. Without it, each receiver decides for itself and fakes often get through."
		if len(parents) > 0 {
			msg += fmt.Sprintf(" Neither %s nor %s has one.", d, joinAnd(parentNames(d)))
		}
		a.add(SevProblem, areaMailSec, "dmarc_missing", msg,
			fmt.Sprintf("Add a TXT record at _dmarc.%s. A safe start is \"v=DMARC1; p=none; rua=mailto:you@%s\" (use a mailbox you read) to collect reports, then move to p=quarantine and then p=reject once the reports show only your real senders.", d, d))
		return dmarcState{known: true}
	case 1:
	default:
		a.add(SevProblem, areaMailSec, "dmarc_multiple",
			fmt.Sprintf("There are %d DMARC records at %s. Receivers ignore DMARC when there is more than one.", len(records), src.Name),
			fmt.Sprintf("Keep one DMARC record at %s and delete the others.", src.Name))
		return dmarcState{known: true, present: true}
	}
	rec := parseDMARC(records[0])
	policy, tag := rec.Policy, "p"
	if inherited && rec.Policy != "" && rec.SubPolicy != "" {
		policy, tag = rec.SubPolicy, "sp"
	}
	a.rep.DMARC = &DMARCSummary{Record: rec.Raw, FoundAt: src.Name, Policy: rec.Policy, SubdomainPolicy: rec.SubPolicy,
		AppliedPolicy: policy, Pct: rec.Pct, Reports: rec.RUA}
	if a.rep.DMARC.Reports == nil {
		a.rep.DMARC.Reports = []string{}
	}
	st := dmarcState{known: true, present: true, policy: policy, tag: tag, pct: rec.Pct}
	lead := fmt.Sprintf("DMARC is set to %s=%s", tag, policy)
	where := "the DMARC record"
	if inherited {
		lead = fmt.Sprintf("%s has no DMARC record of its own, so the one at %s applies. It sets %s=%s", d, src.Name, tag, policy)
		where = "the DMARC record at " + src.Name
	}
	switch policy {
	case "":
		a.add(SevProblem, areaMailSec, "dmarc_invalid",
			fmt.Sprintf("The DMARC record at %s has no valid policy (p=none, p=quarantine or p=reject), so receivers ignore it: %s", src.Name, short(rec.Raw, 120)),
			fmt.Sprintf("Fix the DMARC record at %s so it has a policy, for example \"v=DMARC1; p=none; rua=mailto:you@%s\".", src.Name, d))
	case "none":
		fix := fmt.Sprintf("Once the DMARC reports show that all your real email passes, change %s=none to %s=quarantine, then to %s=reject.", tag, tag, tag)
		if len(rec.RUA) == 0 {
			fix = fmt.Sprintf("Add rua=mailto:<a mailbox you read> to %s so you get reports, then, once they show all your real email passes, change %s=none to %s=quarantine and then %s=reject.", where, tag, tag, tag)
		}
		a.add(SevWarning, areaMailSec, "dmarc_none",
			lead+", which is monitoring only. Receivers may report fakes to you, but they are still told to deliver them.", fix)
	case "quarantine":
		a.add(SevOK, areaMailSec, "dmarc_quarantine", lead+", so email that fails the checks should go to spam.", "")
	case "reject":
		a.add(SevOK, areaMailSec, "dmarc_reject", lead+", so email that fails the checks should be refused.", "")
	}
	enforcing := policy == "quarantine" || policy == "reject"
	if enforcing && rec.Pct < 100 {
		a.add(SevWarning, areaMailSec, "dmarc_pct",
			fmt.Sprintf("DMARC applies its policy to only %d%% of failing email (pct=%d). The rest is treated as if the policy were p=none.", rec.Pct, rec.Pct),
			"Remove pct= from the DMARC record (or set it to 100) so the policy covers all email.")
	}
	if enforcing && !inherited && rec.SubPolicy == "none" {
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
	switch {
	case len(found) > 0:
		msg := fmt.Sprintf("A DKIM signing key was found at selector %s.", found[0])
		if len(found) > 1 {
			msg = fmt.Sprintf("DKIM signing keys were found at selectors %s.", joinAnd(found))
		}
		a.add(SevOK, areaMailSec, "dkim_found", msg, "")
	case len(revoked) == tried:
		// Every selector answers with an empty key. That is a domain-wide
		// "no DKIM keys here" (usually a wildcard), the normal setup for a
		// domain that sends no email, so there is nothing to fix.
		a.add(SevNote, areaMailSec, "dkim_all_revoked",
			fmt.Sprintf("All %d DKIM selector names checked return an empty key. That is how a domain says it does not sign email, which is normal if it sends no email.", tried), "")
		return
	default:
		a.add(SevNote, areaMailSec, "dkim_none_found",
			fmt.Sprintf("No DKIM key was found at the %d common selector names checked. DKIM may still be set up under a name this check did not try.", tried),
			"Turn on DKIM signing in your email provider (and in any service that sends email for you) and publish the record it gives you. If DKIM is already on, run this check again with -selectors and your selector name.")
	}
	switch len(revoked) {
	case 0:
	case 1:
		a.add(SevNote, areaMailSec, "dkim_revoked",
			fmt.Sprintf("DKIM selector %s has an empty key, which means that key was withdrawn.", revoked[0]), "")
	default:
		a.add(SevNote, areaMailSec, "dkim_revoked",
			fmt.Sprintf("DKIM selectors %s have empty keys, which means those keys were withdrawn.", joinAnd(revoked)), "")
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

func (a *analyzer) domainSecurity(dnssecBroken bool) {
	a.caa()
	d := a.rep.Domain
	ds := a.rep.record("ds")
	if a.unknown(ds, areaDomainSec) {
		return
	}
	on, at, failed := a.signed()
	if failed != nil {
		a.unknown(failed, areaDomainSec)
		return
	}
	if on {
		a.rep.DNSSEC = true
		if dnssecBroken {
			return // zoneHealth already reported it
		}
		msg := "DNSSEC is on (a DS record is published at the registry), so resolvers can detect forged DNS answers for this domain."
		if at != d {
			msg = fmt.Sprintf("DNSSEC is on for %s, which %s is part of, so resolvers can detect forged DNS answers for it.", at, d)
		}
		a.add(SevOK, areaDomainSec, "dnssec_on", msg, "")
		return
	}
	a.add(SevNote, areaDomainSec, "dnssec_off",
		"DNSSEC is off. DNSSEC lets resolvers detect forged DNS answers for this domain.",
		"Optional: turn on DNSSEC in your DNS provider's settings, then add the DS record it gives you at your domain registrar.")
}

// caa reports on CAA records. Certificate authorities use the nearest CAA
// records going up the name, so a domain without its own uses its parent's
// (RFC 8659 section 3).
func (a *analyzer) caa() {
	d := a.rep.Domain
	caa := a.rep.record("caa")
	if a.unknown(caa, areaDomainSec) {
		return
	}
	values, at := caa.Values, d
	if len(values) == 0 {
		for _, p := range a.parents("parent-caa:") {
			if a.unknown(p, areaDomainSec) {
				return
			}
			if len(p.Values) > 0 {
				values, at = p.Values, p.Name
				break
			}
		}
	}
	var issuers []string
	for _, v := range values {
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
	case len(issuers) > 0 && at == d:
		a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("CAA limits who may issue certificates for %s to: %s.", d, strings.Join(issuers, ", ")), "")
	case len(issuers) > 0:
		a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("The CAA records of %s limit who may issue certificates for %s to: %s.", at, d, strings.Join(issuers, ", ")), "")
	case len(values) > 0 && at == d:
		a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("CAA records are published for %s.", d), "")
	case len(values) > 0:
		a.add(SevOK, areaDomainSec, "caa_ok", fmt.Sprintf("The CAA records of %s also cover %s.", at, d), "")
	default:
		a.add(SevNote, areaDomainSec, "caa_missing",
			fmt.Sprintf("No CAA record, so any certificate authority may issue a certificate for %s.", d),
			"Optional: add a CAA record naming the certificate authority you use, for example 0 issue \"letsencrypt.org\" if your certificates come from Let's Encrypt.")
	}
}

// addressIDs are records where different answers can be normal (CDNs hand out
// different addresses in different places).
var addressIDs = map[string]bool{"a": true, "aaaa": true, "www": true}

// withoutSerial drops the serial number and timers from SOA answers. Many
// providers change the serial on every edit or re-signing, and resolvers
// cache it for different lengths of time, so a serial difference alone means
// nothing to the domain owner.
func withoutSerial(per []ResolverAnswer) []ResolverAnswer {
	out := slices.Clone(per)
	for i := range out {
		vals := make([]string, len(out[i].Values))
		for j, v := range out[i].Values {
			f := strings.Fields(v)
			if len(f) > 2 {
				f = f[:2]
			}
			vals[j] = strings.Join(f, " ")
		}
		out[i].Values = vals
	}
	return out
}

func (a *analyzer) disagreements() {
	disagree := false
	for _, r := range a.rep.Records {
		per := r.PerResolver
		if r.ID == "soa" {
			per = withoutSerial(per)
		}
		groups := answerGroups(per)
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
	// Only resolvers that answered most lookups count as compared: one that
	// answered a single lookup proves little by agreeing.
	compared := 0
	for ri := range a.rep.Resolvers {
		answered := 0
		for _, r := range a.rep.Records {
			if ri < len(r.PerResolver) && r.PerResolver[ri].Error == "" {
				answered++
			}
		}
		if len(a.rep.Records) > 0 && answered*2 > len(a.rep.Records) {
			compared++
		}
	}
	all := compared == len(a.rep.Resolvers)
	switch {
	case compared == 2 && all:
		a.add(SevOK, areaResolvers, "resolvers_agree", "Both resolvers gave the same answers.", "")
	case compared == 2:
		a.add(SevOK, areaResolvers, "resolvers_agree", "Both resolvers that answered gave the same answers.", "")
	case compared > 2 && all:
		a.add(SevOK, areaResolvers, "resolvers_agree", fmt.Sprintf("All %d resolvers gave the same answers.", compared), "")
	case compared > 2:
		a.add(SevOK, areaResolvers, "resolvers_agree", fmt.Sprintf("All %d resolvers that answered gave the same answers.", compared), "")
	case len(a.rep.Resolvers) == 1:
		a.add(SevNote, areaResolvers, "single_resolver", "Only one resolver was asked, so answers could not be compared.", "")
	case compared == 1:
		a.add(SevNote, areaResolvers, "single_resolver", "Only one resolver answered most of the lookups, so answers could not be compared.", "")
	default:
		a.add(SevNote, areaResolvers, "single_resolver", "No resolver answered most of the lookups, so answers could not be compared.", "")
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
// comes from the domain, meaning the From line people see. Only an enforcing
// DMARC policy tells receivers to check that line: SPF on its own checks the
// hidden sender address (the envelope), which a faker can set to any domain
// they control.
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
	tag := d.tag
	if tag == "" {
		tag = "p"
	}
	dm := "there is no DMARC policy"
	switch {
	case d.policy == "none":
		dm = "DMARC is set to monitoring only (" + tag + "=none)"
	case d.present:
		dm = "the DMARC record is not valid"
	}
	switch s {
	case spfHard, spfSoft, spfRedirect:
		return Verdict{Answer: "Yes", Reason: dm + ", so nothing tells receiving mail servers to block a fake that shows " + domain + " in the From line people see. SPF is set up, but on its own it only stops fakes that also forge the hidden sender address, which a faker does not need to do."}
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
