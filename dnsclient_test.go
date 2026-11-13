package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func queryValues(t *testing.T, c *Client, r Resolver, name string, qt dnsmessage.Type) []string {
	t.Helper()
	resp, err := c.Query(context.Background(), r, name, qt)
	if err != nil {
		t.Fatalf("Query(%s, %s): %v", name, typeName(qt), err)
	}
	var out []string
	for _, a := range resp.Answers {
		out = append(out, a.Type+" "+a.Value)
	}
	return out
}

func TestQueryReadsEveryRecordType(t *testing.T) {
	z := newZone().
		add("types.test",
			rrA("192.0.2.1"), rrAAAA("2001:db8::1"), rrNS("ns1.types.test"),
			rrSOA("ns1.types.test", 42), rrMX(5, "mx.types.test"),
			rrTXT("v=spf1 ", "-all"), rrCAA(0, "issue", "letsencrypt.org"),
			rrDS(2371, 13, 2, []byte{0xab, 0xcd})).
		add("alias.types.test", rrCNAME("types.test"))
	srv := startFakeDNS(t, z)
	c := NewClient(2*time.Second, 4)
	r := srv.resolver()

	cases := []struct {
		name string
		qt   dnsmessage.Type
		want []string
	}{
		{"types.test", dnsmessage.TypeA, []string{"A 192.0.2.1"}},
		{"types.test", dnsmessage.TypeAAAA, []string{"AAAA 2001:db8::1"}},
		{"types.test", dnsmessage.TypeNS, []string{"NS ns1.types.test"}},
		{"types.test", dnsmessage.TypeSOA, []string{"SOA ns1.types.test hostmaster.ns1.types.test 42 7200 3600 1209600 300"}},
		{"types.test", dnsmessage.TypeMX, []string{"MX 5 mx.types.test"}},
		// Split TXT strings are joined with nothing in between.
		{"types.test", dnsmessage.TypeTXT, []string{"TXT v=spf1 -all"}},
		{"types.test", typeCAA, []string{`CAA 0 issue "letsencrypt.org"`}},
		{"types.test", typeDS, []string{"DS 2371 13 2 ABCD"}},
		{"alias.types.test", dnsmessage.TypeA, []string{"CNAME types.test", "A 192.0.2.1"}},
	}
	for _, tc := range cases {
		got := queryValues(t, c, r, tc.name, tc.qt)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: got %q, want %q", tc.name, typeName(tc.qt), got, tc.want)
		}
	}
}

func TestQueryFallsBackToTCPWhenTruncated(t *testing.T) {
	z := newZone().add("big.test", rrTXT("v=spf1 include:_spf.big.test -all"))
	z.truncate["big.test"] = true
	srv := startFakeDNS(t, z)
	c := NewClient(2*time.Second, 4)

	resp, err := c.Query(context.Background(), srv.resolver(), "big.test", dnsmessage.TypeTXT)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !resp.UsedTCP {
		t.Error("UsedTCP = false, want true after a truncated UDP answer")
	}
	if len(resp.Answers) != 1 || resp.Answers[0].Value != "v=spf1 include:_spf.big.test -all" {
		t.Errorf("answers = %+v", resp.Answers)
	}
	if srv.udpQueries.Load() == 0 || srv.tcpQueries.Load() == 0 {
		t.Errorf("udp=%d tcp=%d, want both used", srv.udpQueries.Load(), srv.tcpQueries.Load())
	}
}

func TestQueryNXDomainIsNotAnError(t *testing.T) {
	srv := startFakeDNS(t, newZone().add("here.test", rrA("192.0.2.1")))
	c := NewClient(2*time.Second, 4)
	resp, err := c.Query(context.Background(), srv.resolver(), "missing.test", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.RCode != dnsmessage.RCodeNameError || len(resp.Answers) != 0 {
		t.Errorf("rcode=%v answers=%v, want NXDOMAIN and none", resp.RCode, resp.Answers)
	}
}

func TestQueryUnreachableResolverFails(t *testing.T) {
	c := NewClient(400*time.Millisecond, 4)
	r := Resolver{Name: "dead", Addrs: []string{closedAddr(t)}}
	_, err := c.Query(context.Background(), r, "example.test", dnsmessage.TypeA)
	if err == nil {
		t.Fatal("Query to a closed port succeeded")
	}
	var rc *RCodeError
	if errors.As(err, &rc) {
		t.Errorf("got an RCodeError (%v), want a network error", err)
	}
	if msg := plainError(err); msg != "connection refused" && msg != "no answer in time" {
		t.Errorf("plainError = %q", msg)
	}
}

func TestQueryTriesNextSystemAddress(t *testing.T) {
	srv := startFakeDNS(t, newZone().add("ok.test", rrA("192.0.2.7")))
	c := NewClient(400*time.Millisecond, 4)
	r := Resolver{Name: "system", Addrs: []string{closedAddr(t), srv.addr}}
	got := queryValues(t, c, r, "ok.test", dnsmessage.TypeA)
	if !slices.Equal(got, []string{"A 192.0.2.7"}) {
		t.Errorf("got %q", got)
	}
}

func TestDecodeRejectsShortRecords(t *testing.T) {
	if _, err := decodeCAA([]byte{0}); err == nil {
		t.Error("decodeCAA accepted 1 byte")
	}
	if _, err := decodeCAA([]byte{0, 9, 'a'}); err == nil {
		t.Error("decodeCAA accepted a tag longer than the record")
	}
	if _, err := decodeDS([]byte{1, 2, 3}); err == nil {
		t.Error("decodeDS accepted 3 bytes")
	}
}

func TestRunBoundedRespectsLimit(t *testing.T) {
	var mu = make(chan struct{}, 1)
	running, peak := 0, 0
	runBounded(context.Background(), 50, 3, func(ctx context.Context, i int) {
		mu <- struct{}{}
		running++
		peak = max(peak, running)
		<-mu
		time.Sleep(2 * time.Millisecond)
		mu <- struct{}{}
		running--
		<-mu
	})
	if peak > 3 || peak == 0 {
		t.Errorf("peak concurrency = %d, want 1..3", peak)
	}
}
