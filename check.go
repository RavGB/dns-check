package main

import (
	"context"
	"fmt"
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
