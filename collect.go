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
	return qs
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

// collect asks every resolver every query. All (resolver, query) pairs run in
// parallel, at most limit at a time. Each goroutine writes only its own slot
// in the result slices, so no locking is needed.
func collect(ctx context.Context, c *Client, resolvers []Resolver, queries []Query, limit int) []QueryResult {
	results := make([]QueryResult, len(queries))
	for i, q := range queries {
		results[i] = QueryResult{Query: q, Lookups: make([]Lookup, len(resolvers))}
	}
	health := make([]resolverHealth, len(resolvers))
	nr := len(resolvers)
	runBounded(ctx, len(queries)*nr, limit, func(ctx context.Context, k int) {
		qi, ri := k/nr, k%nr
		h := &health[ri]
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

// toLookup keeps the records of the asked type (and CNAMEs for www).
func toLookup(q Query, resp *Response) Lookup {
	l := Lookup{NXDomain: resp.RCode == dnsmessage.RCodeNameError, UsedTCP: resp.UsedTCP}
	want := typeName(q.Type)
	for _, a := range resp.Answers {
		var v string
		switch {
		case q.KeepCNAME && (a.Type == "CNAME" || a.Type == want):
			v = a.Type + " " + a.Value
		case a.Type == want:
			v = a.Value
		default:
			continue
		}
		l.Values = append(l.Values, v)
		l.TTL = max(l.TTL, a.TTL)
	}
	slices.Sort(l.Values)
	l.Values = slices.Compact(l.Values)
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
