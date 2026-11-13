package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// zone is a tiny in-memory DNS zone for tests. It must not change after the
// server using it has started.
type zone struct {
	records  map[string][]dnsmessage.ResourceBody // key: name + "|" + type
	names    map[string]bool                      // names that exist (others get NXDOMAIN)
	truncate map[string]bool                      // names whose UDP answers are cut off
}

func newZone() *zone {
	return &zone{records: map[string][]dnsmessage.ResourceBody{}, names: map[string]bool{}, truncate: map[string]bool{}}
}

func bodyType(b dnsmessage.ResourceBody) dnsmessage.Type {
	switch r := b.(type) {
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	case *dnsmessage.AAAAResource:
		return dnsmessage.TypeAAAA
	case *dnsmessage.NSResource:
		return dnsmessage.TypeNS
	case *dnsmessage.CNAMEResource:
		return dnsmessage.TypeCNAME
	case *dnsmessage.SOAResource:
		return dnsmessage.TypeSOA
	case *dnsmessage.MXResource:
		return dnsmessage.TypeMX
	case *dnsmessage.TXTResource:
		return dnsmessage.TypeTXT
	case *dnsmessage.UnknownResource:
		return r.Type
	}
	panic("unsupported record type in test zone")
}

func zkey(name string, t dnsmessage.Type) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "|" + typeName(t)
}

// add puts records at name and returns the zone so calls can be chained.
func (z *zone) add(name string, bodies ...dnsmessage.ResourceBody) *zone {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	z.names[name] = true
	for _, b := range bodies {
		k := zkey(name, bodyType(b))
		z.records[k] = append(z.records[k], b)
	}
	return z
}

// remove deletes all records of type t at name. The name keeps existing.
func (z *zone) remove(name string, t dnsmessage.Type) *zone {
	delete(z.records, zkey(name, t))
	return z
}

func mustName(s string) dnsmessage.Name {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return dnsmessage.MustNewName(s)
}

func rrA(ip string) *dnsmessage.AResource {
	return &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}
}

func rrAAAA(ip string) *dnsmessage.AAAAResource {
	return &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()}
}

func rrNS(host string) *dnsmessage.NSResource { return &dnsmessage.NSResource{NS: mustName(host)} }

func rrCNAME(host string) *dnsmessage.CNAMEResource {
	return &dnsmessage.CNAMEResource{CNAME: mustName(host)}
}

func rrMX(pref uint16, host string) *dnsmessage.MXResource {
	return &dnsmessage.MXResource{Pref: pref, MX: mustName(host)}
}

func rrTXT(parts ...string) *dnsmessage.TXTResource { return &dnsmessage.TXTResource{TXT: parts} }

func rrSOA(ns string, serial uint32) *dnsmessage.SOAResource {
	return &dnsmessage.SOAResource{NS: mustName(ns), MBox: mustName("hostmaster." + ns), Serial: serial, Refresh: 7200, Retry: 3600, Expire: 1209600, MinTTL: 300}
}

func rrCAA(flags byte, tag, value string) *dnsmessage.UnknownResource {
	data := append([]byte{flags, byte(len(tag))}, tag...)
	data = append(data, value...)
	return &dnsmessage.UnknownResource{Type: typeCAA, Data: data}
}

func rrDS(keyTag uint16, alg, digestType byte, digest []byte) *dnsmessage.UnknownResource {
	data := binary.BigEndian.AppendUint16(nil, keyTag)
	data = append(data, alg, digestType)
	data = append(data, digest...)
	return &dnsmessage.UnknownResource{Type: typeDS, Data: data}
}

// answer looks up a question, following one CNAME like a resolver would.
func (z *zone) answer(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if !z.names[name] {
		return dnsmessage.RCodeNameError, nil
	}
	var out []dnsmessage.Resource
	addAll := func(owner string, t dnsmessage.Type) {
		for _, b := range z.records[zkey(owner, t)] {
			out = append(out, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: mustName(owner), Class: dnsmessage.ClassINET, TTL: 300},
				Body:   b,
			})
		}
	}
	addAll(name, q.Type)
	if len(out) == 0 && q.Type != dnsmessage.TypeCNAME {
		if cn := z.records[zkey(name, dnsmessage.TypeCNAME)]; len(cn) > 0 {
			addAll(name, dnsmessage.TypeCNAME)
			target := strings.TrimSuffix(cn[0].(*dnsmessage.CNAMEResource).CNAME.String(), ".")
			addAll(target, q.Type)
		}
	}
	return dnsmessage.RCodeSuccess, out
}

// fakeDNS serves a zone on 127.0.0.1 over UDP and TCP, on the same port.
type fakeDNS struct {
	addr       string
	zone       *zone
	udpQueries atomic.Int64
	tcpQueries atomic.Int64
}

func startFakeDNS(t *testing.T, z *zone) *fakeDNS {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for attempt := 0; attempt < 50; attempt++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		l, err := net.Listen("tcp", p.LocalAddr().String())
		if err == nil {
			pc, ln = p, l
			break
		}
		p.Close()
	}
	if pc == nil {
		t.Fatal("could not get the same UDP and TCP port")
	}
	s := &fakeDNS{addr: pc.LocalAddr().String(), zone: z}
	t.Cleanup(func() {
		pc.Close()
		ln.Close()
	})

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.udpQueries.Add(1)
			if resp := s.handle(buf[:n], true); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveTCP(conn)
		}
	}()
	return s
}

func (s *fakeDNS) serveTCP(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		s.tcpQueries.Add(1)
		resp := s.handle(msg, false)
		if resp == nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		if _, err := conn.Write(append(out, resp...)); err != nil {
			return
		}
	}
}

func (s *fakeDNS) handle(msg []byte, udp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q},
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if udp && s.zone.truncate[name] {
		resp.Header.Truncated = true
	} else {
		resp.Header.RCode, resp.Answers = s.zone.answer(q)
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

// resolver returns a Resolver pointing at this fake server.
func (s *fakeDNS) resolver() Resolver { return Resolver{Name: s.addr, Addrs: []string{s.addr}} }

// closedAddr returns a local UDP address that nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := p.LocalAddr().String()
	p.Close()
	return addr
}
