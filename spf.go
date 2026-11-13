package main

import (
	"context"
	"slices"
	"strings"
)

// spfRecord is a parsed SPF record (RFC 7208).
type spfRecord struct {
	Raw      string
	All      string   // qualifier of the first "all" term: "+", "-", "~", "?", or "" when there is none
	AllTerm  string   // the first "all" term as written, for example "-all"
	AfterAll []string // mechanisms after the first "all"; receivers never reach them
	Redirect string
	Includes []string
	Lookups  int      // terms in this record that cost a DNS lookup
	HasPTR   bool     // uses the discouraged ptr mechanism
	Unknown  []string // terms receivers would not understand
	Macro    bool     // has include or redirect targets with macros, which cannot be followed
}

// isSPF reports whether a TXT value is an SPF record.
func isSPF(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	return t == "v=spf1" || strings.HasPrefix(t, "v=spf1 ")
}

// parseSPF reads the terms of an SPF record and counts the ones that need a
// DNS lookup: include, a, mx, ptr, exists, and the redirect modifier.
// Receivers read mechanisms from left to right and the first "all" always
// matches, so mechanisms after it are never used and cost no lookups (RFC
// 7208 section 5.1). They are still checked for syntax, because a syntax
// error anywhere breaks the whole record.
func parseSPF(raw string) spfRecord {
	rec := spfRecord{Raw: raw}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return rec
	}
	for _, term := range fields[1:] {
		lower := strings.ToLower(term)
		// A modifier looks like name=value, with the name before any ':' or '/'.
		if i := strings.IndexAny(lower, "=:/"); i > 0 && lower[i] == '=' {
			if lower[:i] == "redirect" {
				rec.Redirect = lower[i+1:]
			}
			// exp= and unknown modifiers need no lookup during the check.
			continue
		}
		qualifier := "+"
		if strings.ContainsAny(lower[:1], "+-~?") {
			qualifier, lower = lower[:1], lower[1:]
		}
		name, arg := lower, ""
		if i := strings.IndexAny(lower, ":/"); i >= 0 {
			name = lower[:i]
			if lower[i] == ':' {
				arg = lower[i+1:]
			}
		}
		if rec.AllTerm != "" {
			switch name {
			case "all", "a", "mx", "ptr", "exists", "ip4", "ip6":
				rec.AfterAll = append(rec.AfterAll, term)
			case "include":
				if arg != "" {
					rec.AfterAll = append(rec.AfterAll, term)
				} else {
					rec.Unknown = append(rec.Unknown, term)
				}
			default:
				rec.Unknown = append(rec.Unknown, term)
			}
			continue
		}
		switch name {
		case "all":
			rec.All = qualifier
			rec.AllTerm = term
		case "include":
			rec.Lookups++
			if arg == "" {
				rec.Unknown = append(rec.Unknown, term)
				continue
			}
			rec.Includes = append(rec.Includes, arg)
		case "a", "mx", "exists":
			rec.Lookups++
		case "ptr":
			rec.Lookups++
			rec.HasPTR = true
		case "ip4", "ip6":
		default:
			rec.Unknown = append(rec.Unknown, term)
		}
	}
	// redirect is only used when there is no "all" term.
	if rec.Redirect != "" && rec.All == "" {
		rec.Lookups++
	}
	for _, t := range rec.followTargets() {
		if strings.Contains(t, "%") {
			rec.Macro = true
		}
	}
	return rec
}

// followTargets lists the include and redirect domains whose SPF records also
// count toward the lookup limit.
func (r spfRecord) followTargets() []string {
	out := slices.Clone(r.Includes)
	if r.Redirect != "" && r.All == "" {
		out = append(out, r.Redirect)
	}
	return out
}

// targets is followTargets without macro targets, which cannot be looked up.
func (r spfRecord) targets() []string {
	var out []string
	for _, t := range r.followTargets() {
		if !strings.Contains(t, "%") {
			out = append(out, strings.TrimSuffix(t, "."))
		}
	}
	return out
}

// spfExpansion is the result of following includes and redirects.
type spfExpansion struct {
	Lookups  int      // total DNS-lookup terms, counting every include occurrence
	Complete bool     // false when a limit was hit or something could not be fetched
	Missing  []string // include or redirect targets that have no SPF record
	Multiple []string // targets that have more than one SPF record
	Failed   []string // targets that could not be looked up
}

const (
	spfMaxDepth   = 10  // how many include levels to follow
	spfMaxFetches = 40  // how many different domains to fetch at most
	spfMaxQueue   = 200 // how many include occurrences to track per level
)

type spfFetch struct {
	rec   *spfRecord
	count int // number of SPF records found
	err   error
}

// expandSPF follows include and redirect terms level by level, fetching each
// level's domains in parallel, and adds up the DNS lookups the whole record
// needs. Receivers stop at 10 (RFC 7208 section 4.6.4).
func expandSPF(ctx context.Context, lookup func(context.Context, string) ([]string, error), root spfRecord, limit int) spfExpansion {
	exp := spfExpansion{Lookups: root.Lookups, Complete: !root.Macro}
	cache := map[string]spfFetch{}
	level := root.targets()
	for depth := 1; len(level) > 0; depth++ {
		if depth > spfMaxDepth || ctx.Err() != nil {
			exp.Complete = false
			break
		}
		var todo []string
		for _, t := range level {
			if _, done := cache[t]; !done && !slices.Contains(todo, t) {
				todo = append(todo, t)
			}
		}
		if room := spfMaxFetches - len(cache); len(todo) > room {
			todo = todo[:max(room, 0)]
			exp.Complete = false
		}
		got := make([]spfFetch, len(todo))
		runBounded(ctx, len(todo), limit, func(ctx context.Context, i int) {
			txts, err := lookup(ctx, todo[i])
			if err != nil {
				got[i] = spfFetch{err: err}
				return
			}
			var spfs []string
			for _, t := range txts {
				if isSPF(t) {
					spfs = append(spfs, t)
				}
			}
			f := spfFetch{count: len(spfs)}
			if len(spfs) == 1 {
				r := parseSPF(spfs[0])
				f.rec = &r
			}
			got[i] = f
		})
		for i, t := range todo {
			cache[t] = got[i]
		}
		var next []string
		for _, t := range level {
			f, ok := cache[t]
			if !ok {
				continue // over the fetch limit
			}
			switch {
			case f.err != nil:
				exp.Complete = false
				addOnce(&exp.Failed, t)
			case f.count == 0:
				addOnce(&exp.Missing, t)
			case f.count > 1:
				addOnce(&exp.Multiple, t)
			default:
				exp.Lookups += f.rec.Lookups
				if f.rec.Macro {
					exp.Complete = false
				}
				next = append(next, f.rec.targets()...)
			}
		}
		if len(next) > spfMaxQueue {
			next = next[:spfMaxQueue]
			exp.Complete = false
		}
		level = next
	}
	return exp
}

func addOnce(list *[]string, s string) {
	if !slices.Contains(*list, s) {
		*list = append(*list, s)
	}
}
