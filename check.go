package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// checkConfig holds the settings for one run.
type checkConfig struct {
	Selectors   []string
	Concurrency int
}

// checkDomain asks every resolver about the domain at once, compares the
// answers, follows SPF includes, and builds the report. It returns an error
// only when no resolver could be used at all.
func checkDomain(ctx context.Context, c *Client, resolvers []Resolver, domain string, cfg checkConfig) (*Report, error) {
	queries := planQueries(domain, cfg.Selectors)
	results := collect(ctx, c, resolvers, queries, cfg.Concurrency)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("stopped before the check finished")
	}
	var notSeenBy []string
	for _, ri := range dropUnseen(results) {
		notSeenBy = append(notSeenBy, resolvers[ri].Name)
	}
	statuses, usable := resolverStatuses(resolvers, results)
	if len(usable) == 0 {
		var why []string
		for _, st := range statuses {
			why = append(why, st.Name+": "+st.Error)
		}
		return nil, fmt.Errorf("none of the resolvers answered (%s)", strings.Join(why, "; "))
	}
	rep := &Report{
		Domain:        domain,
		CheckedAt:     time.Now().UTC().Truncate(time.Second),
		Resolvers:     statuses,
		Records:       buildRecords(resolvers, results),
		DKIMSelectors: []string{},
		NotSeenBy:     notSeenBy,
	}

	var exp *spfExpansion
	var spfs []string
	for _, v := range rep.record("txt").Values {
		if isSPF(v) {
			spfs = append(spfs, v)
		}
	}
	if len(spfs) == 1 {
		e := expandSPF(ctx, txtLookup(c, resolvers, usable), parseSPF(spfs[0]), cfg.Concurrency)
		exp = &e
	}
	analyze(rep, exp)
	return rep, nil
}

// errNotSeen replaces the answers of a resolver that says the domain does not
// exist while another resolver sees it.
var errNotSeen = errors.New("it does not see this domain yet (it says the domain does not exist)")

// dropUnseen finds resolvers that answered "no such domain" (NXDOMAIN) for the
// domain while at least one other resolver sees it. That usually means a new
// or moved domain has not reached every resolver yet. Their answers are all
// empty, so they are replaced with errNotSeen and the report is built from
// the resolvers that see the domain. It returns the indexes of those
// resolvers.
func dropUnseen(results []QueryResult) []int {
	i := slices.IndexFunc(results, func(qr QueryResult) bool { return qr.ID == "soa" })
	if i < 0 {
		return nil
	}
	var nx []int
	seen := false
	for ri, l := range results[i].Lookups {
		switch {
		case l.Err != nil:
		case l.NXDomain:
			nx = append(nx, ri)
		default:
			seen = true
		}
	}
	if !seen || len(nx) == 0 {
		return nil
	}
	for qi := range results {
		for _, ri := range nx {
			results[qi].Lookups[ri] = Lookup{Err: errNotSeen}
		}
	}
	return nx
}
