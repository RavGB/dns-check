package main

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestParseSPF(t *testing.T) {
	cases := []struct {
		raw      string
		all      string
		lookups  int
		includes []string
		unknown  int
		ptr      bool
		after    []string
	}{
		{"v=spf1 -all", "-", 0, nil, 0, false, nil},
		{"v=spf1 include:_spf.google.com ~all", "~", 1, []string{"_spf.google.com"}, 0, false, nil},
		{"v=spf1 a mx ptr exists:%{i}.x.test ip4:192.0.2.0/24 ip6:2001:db8::/32 +all", "+", 4, nil, 0, true, nil},
		{"v=spf1 a/24 mx:mail.x.test/24 ?all", "?", 2, nil, 0, false, nil},
		{"v=spf1 ip4:192.0.2.1 redirect=_spf.x.test", "", 1, nil, 0, false, nil},
		// redirect is ignored (and costs nothing) when there is an all term.
		{"v=spf1 redirect=_spf.x.test -all", "-", 0, nil, 0, false, nil},
		{"v=spf1 INCLUDE:Upper.Test -ALL", "-", 1, []string{"upper.test"}, 0, false, nil},
		{"v=spf1 include: bogus -all", "-", 1, nil, 2, false, nil},
		{"v=spf1 exp=explain.x.test -all", "-", 0, nil, 0, false, nil},
		// The first all wins; later terms are never reached and cost nothing.
		{"v=spf1 +all -all", "+", 0, nil, 0, false, []string{"-all"}},
		{"v=spf1 include:_spf.first.test ~all include:big.first.test -all", "~", 1, []string{"_spf.first.test"}, 0, false,
			[]string{"include:big.first.test", "-all"}},
		{"v=spf1 -all a mx ptr", "-", 0, nil, 0, false, []string{"a", "mx", "ptr"}},
		// A syntax error after all still breaks the record.
		{"v=spf1 -all bogus include:", "-", 0, nil, 2, false, nil},
	}
	for _, tc := range cases {
		r := parseSPF(tc.raw)
		if r.All != tc.all || r.Lookups != tc.lookups || len(r.Unknown) != tc.unknown || r.HasPTR != tc.ptr {
			t.Errorf("parseSPF(%q) = all %q lookups %d unknown %v ptr %v; want %q %d %d %v",
				tc.raw, r.All, r.Lookups, r.Unknown, r.HasPTR, tc.all, tc.lookups, tc.unknown, tc.ptr)
		}
		if !slices.Equal(r.AfterAll, tc.after) {
			t.Errorf("parseSPF(%q) after all = %q, want %q", tc.raw, r.AfterAll, tc.after)
		}
		if !slices.Equal(r.Includes, tc.includes) {
			t.Errorf("parseSPF(%q) includes = %q, want %q", tc.raw, r.Includes, tc.includes)
		}
	}
}

func TestIsSPF(t *testing.T) {
	for s, want := range map[string]bool{
		"v=spf1 -all":       true,
		"V=SPF1 -all":       true,
		"v=spf1":            true,
		"v=spf10 -all":      false,
		"google-site=abc":   false,
		"  v=spf1 mx -all ": true,
	} {
		if got := isSPF(s); got != want {
			t.Errorf("isSPF(%q) = %v, want %v", s, got, want)
		}
	}
}

// mapLookup serves TXT records from a map, standing in for DNS.
func mapLookup(m map[string][]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		v, ok := m[name]
		if !ok {
			return nil, nil
		}
		if v == nil {
			return nil, errors.New("lookup failed")
		}
		return v, nil
	}
}

func TestExpandSPFCountsNestedIncludes(t *testing.T) {
	m := map[string][]string{
		"a.test": {"v=spf1 a mx ptr -all"},            // 3
		"b.test": {"v=spf1 a mx ptr -all"},            // 3
		"c.test": {"v=spf1 include:d.test -all"},      // 1
		"d.test": {"v=spf1 a mx -all", "unrelated"},   // 2
		"e.test": {"v=spf1 ip4:192.0.2.0/24 ~all"},    // 0
		"f.test": {"not spf"},                         // no SPF
		"g.test": {"v=spf1 -all", "v=spf1 a -all"},    // two SPF records
		"h.test": nil,                                 // lookup error
		"i.test": {"v=spf1 redirect=e.test"},          // 1
		"j.test": {"v=spf1 include:%{d}.x.test -all"}, // 1, macro
	}
	root := parseSPF("v=spf1 include:a.test include:b.test include:c.test -all") // 3
	exp := expandSPF(context.Background(), mapLookup(m), root, 4)
	if exp.Lookups != 12 || !exp.Complete {
		t.Errorf("lookups=%d complete=%v, want 12 true", exp.Lookups, exp.Complete)
	}

	root = parseSPF("v=spf1 include:f.test include:g.test include:h.test include:i.test -all")
	exp = expandSPF(context.Background(), mapLookup(m), root, 4)
	if !slices.Equal(exp.Missing, []string{"f.test"}) || !slices.Equal(exp.Multiple, []string{"g.test"}) || !slices.Equal(exp.Failed, []string{"h.test"}) {
		t.Errorf("missing=%v multiple=%v failed=%v", exp.Missing, exp.Multiple, exp.Failed)
	}
	if exp.Complete {
		t.Error("complete = true after a failed lookup")
	}
	if exp.Lookups != 5 { // 4 includes + 1 redirect inside i.test
		t.Errorf("lookups = %d, want 5", exp.Lookups)
	}

	exp = expandSPF(context.Background(), mapLookup(m), parseSPF("v=spf1 include:j.test -all"), 4)
	if exp.Complete || exp.Lookups != 2 {
		t.Errorf("macro include: lookups=%d complete=%v, want 2 false", exp.Lookups, exp.Complete)
	}
}

func TestExpandSPFStopsOnLoops(t *testing.T) {
	m := map[string][]string{"loop.test": {"v=spf1 include:loop.test -all"}}
	exp := expandSPF(context.Background(), mapLookup(m), parseSPF("v=spf1 include:loop.test -all"), 4)
	if exp.Complete {
		t.Error("complete = true for an include loop")
	}
	if exp.Lookups <= 10 {
		t.Errorf("lookups = %d, want more than 10 for a loop", exp.Lookups)
	}
}
