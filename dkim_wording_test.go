package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A domain that sends no email often publishes an empty DKIM key for every
// selector. That must read as normal, not as "no DKIM key found" plus a list
// of withdrawn keys, and must not ask the owner to turn on DKIM.
func TestDKIMAllSelectorsWithdrawn(t *testing.T) {
	d := "parked.test"
	z := goodZone(d).remove("google._domainkey."+d, dnsmessage.TypeTXT)
	for _, sel := range defaultSelectors {
		z.add(sel+"._domainkey."+d, rrTXT("v=DKIM1; p="))
	}
	rep := check(t, d, z)
	f := wantFinding(t, rep, "dkim_all_revoked", SevNote, "does not sign email")
	if f.Fix != "" {
		t.Errorf("dkim_all_revoked should have no fix, got %q", f.Fix)
	}
	for _, code := range []string{"dkim_none_found", "dkim_revoked", "dkim_found"} {
		if findCode(rep, code) != nil {
			t.Errorf("unexpected finding %s when every selector is withdrawn", code)
		}
	}
}

func TestDKIMWithdrawnSelectorsGrammar(t *testing.T) {
	d := "two.test"
	z := goodZone(d)
	z.add("s1._domainkey."+d, rrTXT("v=DKIM1; p="))
	z.add("s2._domainkey."+d, rrTXT("v=DKIM1; p="))
	rep := check(t, d, z)
	wantFinding(t, rep, "dkim_found", SevOK)
	wantFinding(t, rep, "dkim_revoked", SevNote, "selectors s1 and s2 have empty keys", "those keys were withdrawn")

	one := goodZone(d)
	one.add("k1._domainkey."+d, rrTXT("v=DKIM1; p="))
	wantFinding(t, check(t, d, one), "dkim_revoked", SevNote, "selector k1 has an empty key")
}

// Optional fixes lose their "Optional: " prefix in the text report, so each
// numbered line must still start with a capital letter.
func TestOptionalFixesStartWithACapital(t *testing.T) {
	d := "plain.test"
	z := goodZone(d).remove(d, typeCAA).remove(d, typeDS)
	var buf bytes.Buffer
	writeText(&buf, check(t, d, z), false)
	out := buf.String()
	if !strings.Contains(out, "Optional improvements") {
		t.Fatalf("expected optional improvements in:\n%s", out)
	}
	if m := regexp.MustCompile(`(?m)^\s+\d+\. [a-z]`).FindString(out); m != "" {
		t.Errorf("numbered fix starts with a lowercase letter: %q\n%s", m, out)
	}
}

func TestUpperFirst(t *testing.T) {
	for in, want := range map[string]string{"add a CAA": "Add a CAA", "": "", "Éé": "Éé", "été": "Été"} {
		if got := upperFirst(in); got != want {
			t.Errorf("upperFirst(%q) = %q, want %q", in, got, want)
		}
	}
}
