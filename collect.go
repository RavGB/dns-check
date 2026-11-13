package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// defaultSelectors are the DKIM selector names tried when -selectors is not given.
var defaultSelectors = []string{
	"default", "selector1", "selector2", "google", "k1", "s1", "s2", "dkim",
	"mail", "smtp", "mxvault", "protonmail", "zoho", "resend",
}

// Query is one DNS question the check asks every resolver.
type Query struct {
	ID    string
	Label string
	Name  string
	Type  dnsmessage.Type
	// KeepCNAME keeps CNAME records from the answer as well as the asked
	// type. Used for www, where the CNAME target is worth showing.
	KeepCNAME bool
}

// planQueries lists every question asked for a domain.
func planQueries(domain string, selectors []string) []Query {
	qs := []Query{
		{ID: "a", Label: "website address (A)", Name: domain, Type: dnsmessage.TypeA},
		{ID: "aaaa", Label: "IPv6 website address (AAAA)", Name: domain, Type: dnsmessage.TypeAAAA},
		{ID: "ns", Label: "name servers (NS)", Name: domain, Type: dnsmessage.TypeNS},
		{ID: "soa", Label: "zone details (SOA)", Name: domain, Type: dnsmessage.TypeSOA},
		{ID: "mx", Label: "mail servers (MX)", Name: domain, Type: dnsmessage.TypeMX},
		{ID: "www", Label: "www address (CNAME and A)", Name: "www." + domain, Type: dnsmessage.TypeA, KeepCNAME: true},
		{ID: "txt", Label: "TXT records (where SPF lives)", Name: domain, Type: dnsmessage.TypeTXT},
		{ID: "dmarc", Label: "DMARC policy (TXT)", Name: "_dmarc." + domain, Type: dnsmessage.TypeTXT},
		{ID: "caa", Label: "certificate rules (CAA)", Name: domain, Type: typeCAA},
		{ID: "ds", Label: "DNSSEC signing (DS)", Name: domain, Type: typeDS},
		{ID: "mta-sts", Label: "MTA-STS (TXT)", Name: "_mta-sts." + domain, Type: dnsmessage.TypeTXT},
		{ID: "tls-rpt", Label: "TLS reporting (TXT)", Name: "_smtp._tls." + domain, Type: dnsmessage.TypeTXT},
		{ID: "bimi", Label: "BIMI logo (TXT)", Name: "default._bimi." + domain, Type: dnsmessage.TypeTXT},
	}
	for _, s := range selectors {
		qs = append(qs, Query{
			ID:    "dkim:" + s,
			Label: "DKIM key, selector " + s + " (TXT)",
			Name:  s + "._domainkey." + domain,
			Type:  dnsmessage.TypeTXT,
		})
	}
	// A subdomain with no DMARC or CAA record of its own uses its parent's,
	// and one without name servers of its own shares the DNSSEC of the zone
	// it lives in. Asking for them up front costs no extra wait.
	for _, p := range parentNames(domain) {
		qs = append(qs,
			Query{ID: "parent-dmarc:" + p, Label: "parent domain's DMARC policy (TXT)", Name: "_dmarc." + p, Type: dnsmessage.TypeTXT},
			Query{ID: "parent-caa:" + p, Label: "parent domain's certificate rules (CAA)", Name: p, Type: typeCAA},
			Query{ID: "parent-ns:" + p, Label: "parent domain's name servers (NS)", Name: p, Type: dnsmessage.TypeNS},
			Query{ID: "parent-ds:" + p, Label: "parent domain's DNSSEC signing (DS)", Name: p, Type: typeDS},
		)
	}
	return qs
}

// maxParents caps how many parent names are asked about for a deep subdomain.
const maxParents = 5

// parentNames lists the parents of domain, nearest first, down to names with
// two labels, leaving out names that look like shared suffixes. For
// shop.example.com that is example.com; for example.co.uk there is none.
// For a very deep name it keeps the nearest parents and the last one, which
// is usually the registered domain.
func parentNames(domain string) []string {
	labels := strings.Split(domain, ".")
	var out []string
	for i := 1; len(labels)-i >= 2; i++ {
		p := strings.Join(labels[i:], ".")
		if looksLikePublicSuffix(p) {
			break
		}
		out = append(out, p)
	}
	if len(out) > maxParents {
		out = append(out[:maxParents-1], out[len(out)-1])
	}
	return out
}

// secondLevelSuffixes are labels that, under a two-letter country code, are
// usually shared suffixes where anyone can register a name, as in co.uk,
// com.au or gc.ca. Some of them publish their own DMARC record (co.za and
// gc.ca do), which does not belong to the domains under them. This tool has
// no full public suffix list, so it covers the common cases.
var secondLevelSuffixes = map[string]bool{
	"ac": true, "asn": true, "co": true, "com": true, "edu": true, "gc": true, "go": true, "gob": true,
	"gouv": true, "gov": true, "govt": true, "id": true, "ltd": true, "me": true, "mil": true, "ne": true,
	"net": true, "nhs": true, "nic": true, "or": true, "org": true, "plc": true, "police": true,
	"sch": true, "school": true, "web": true,
}

// canadianProvinces are the shared suffixes under .ca, as in on.ca.
var canadianProvinces = map[string]bool{
	"ab": true, "bc": true, "mb": true, "nb": true, "nf": true, "nl": true, "ns": true, "nt": true,
	"nu": true, "on": true, "pe": true, "qc": true, "sk": true, "yk": true,
}

// looksLikePublicSuffix reports whether a two-label name such as co.uk is
// probably a shared suffix rather than someone's domain.
func looksLikePublicSuffix(name string) bool {
	first, tld, ok := strings.Cut(name, ".")
	if !ok || strings.Contains(tld, ".") || len(tld) != 2 {
		return false
	}
	return secondLevelSuffixes[first] || (tld == "ca" && canadianProvinces[first])
}

// Lookup is one resolver's answer to one query.
type Lookup struct {
	Values   []string // sorted, without duplicates; this is what gets compared
	TTL      uint32   // the largest TTL in the answer
	NXDomain bool
	UsedTCP  bool
	Err      error
}

// QueryResult holds every resolver's answer to one query, in resolver order.
type QueryResult struct {
	Query
	Lookups []Lookup
}

// errSkipped marks lookups that were not sent because the resolver had
// already failed several times without a single answer.
var errSkipped = errors.New("skipped because this resolver was not answering")

// giveUpAfter is how many failures in a row, with no answer at all, make the
// check stop sending more lookups to a resolver.
const giveUpAfter = 3

type resolverHealth struct {
	answered atomic.Int32
	failed   atomic.Int32
}

// healthOf returns the shared health counters for a resolver. They live in
// the client, so a resolver that is not answering is skipped for the rest of
// the run, not only for the domain being checked.
func (c *Client) healthOf(r Resolver) *resolverHealth {
	key := strings.Join(r.Addrs, ",")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health == nil {
		c.health = map[string]*resolverHealth{}
	}
	h := c.health[key]
	if h == nil {
		h = &resolverHealth{}
		c.health[key] = h
	}
	return h
}

// collect asks every resolver every query. All (resolver, query) pairs run in
// parallel, at most limit at a time. Each goroutine writes only its own slot
// in the result slices, so no locking is needed.
func collect(ctx context.Context, c *Client, resolvers []Resolver, queries []Query, limit int) []QueryResult {
	results := make([]QueryResult, len(queries))
	for i, q := range queries {
		results[i] = QueryResult{Query: q, Lookups: make([]Lookup, len(resolvers))}
	}
	health := make([]*resolverHealth, len(resolvers))
	for i, r := range resolvers {
		health[i] = c.healthOf(r)
	}
	nr := len(resolvers)
	runBounded(ctx, len(queries)*nr, limit, func(ctx context.Context, k int) {
		qi, ri := k/nr, k%nr
		h := health[ri]
		if h.answered.Load() == 0 && h.failed.Load() >= giveUpAfter {
			results[qi].Lookups[ri] = Lookup{Err: errSkipped}
			return
		}
		q := queries[qi]
		resp, err := c.Query(ctx, resolvers[ri], q.Name, q.Type)
		if err != nil {
			var rc *RCodeError
			if errors.As(err, &rc) {
				h.answered.Add(1) // it answered, just not with records
			} else {
				h.failed.Add(1)
			}
			results[qi].Lookups[ri] = Lookup{Err: err}
			return
		}
		h.answered.Add(1)
		results[qi].Lookups[ri] = toLookup(q, resp)
	})
	return results
}

// toLookup keeps the records of the asked type (and CNAMEs for www). Values
// are sorted so answers can be compared, except that a CNAME chain is kept in
// order, starting from the asked name.
func toLookup(q Query, resp *Response) Lookup {
	l := Lookup{NXDomain: resp.RCode == dnsmessage.RCodeNameError, UsedTCP: resp.UsedTCP}
	want := typeName(q.Type)
	var values []string
	cnames := map[string]string{} // owner name -> target
	for _, a := range resp.Answers {
		switch {
		case q.KeepCNAME && a.Type == "CNAME":
			if _, dup := cnames[a.Name]; dup {
				values = append(values, "CNAME "+a.Value)
			} else {
				cnames[a.Name] = a.Value
			}
		case q.KeepCNAME && a.Type == want:
			values = append(values, a.Type+" "+a.Value)
		case a.Type == want:
			values = append(values, a.Value)
		default:
			continue
		}
		l.TTL = max(l.TTL, a.TTL)
	}
	var chain []string
	for name := strings.ToLower(strings.TrimSuffix(q.Name, ".")); len(cnames) > 0; {
		target, ok := cnames[name]
		if !ok {
			break
		}
		chain = append(chain, "CNAME "+target)
		delete(cnames, name)
		name = target
	}
	for _, target := range cnames { // CNAMEs that are not on the chain
		values = append(values, "CNAME "+target)
	}
	slices.Sort(values)
	l.Values = append(chain, slices.Compact(values)...)
	if l.Values == nil {
		l.Values = []string{}
	}
	return l
}

// runBounded calls fn for every index in [0, n) using at most limit
// goroutines at once, and waits for all of them to finish.
func runBounded(ctx context.Context, n, limit int, fn func(ctx context.Context, i int)) {
	if limit < 1 {
		limit = 1
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, limit)
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(ctx, i)
		}(i)
	}
	wg.Wait()
}

// txtLookup returns a function that fetches TXT records from the first
// usable resolver that answers. It is used to follow SPF includes.
func txtLookup(c *Client, resolvers []Resolver, usable []int) func(context.Context, string) ([]string, error) {
	return func(ctx context.Context, name string) ([]string, error) {
		lastErr := errors.New("no resolver available")
		for _, ri := range usable {
			resp, err := c.Query(ctx, resolvers[ri], name, dnsmessage.TypeTXT)
			if err != nil {
				lastErr = err
				if ctx.Err() != nil {
					break
				}
				continue
			}
			var out []string
			for _, a := range resp.Answers {
				if a.Type == "TXT" {
					out = append(out, a.Value)
				}
			}
			return out, nil
		}
		return nil, lastErr
	}
}

// joinValues is the comparison key for a set of answer values.
func joinValues(v []string) string { return strings.Join(v, "\n") }
