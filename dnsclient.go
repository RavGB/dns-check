package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Record types that dnsmessage (and the standard library resolver) do not
// name. They are read as raw data and decoded here.
const (
	typeDS  dnsmessage.Type = 43
	typeCAA dnsmessage.Type = 257
)

// ednsSize is the UDP answer size we advertise, the value recommended by
// DNS Flag Day 2020. Bigger answers come back truncated and are fetched again
// over TCP.
const ednsSize = 1232

// typeName returns the usual short name of a record type.
func typeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case typeDS:
		return "DS"
	case typeCAA:
		return "CAA"
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

// Answer is one record from the answer section of a DNS response.
type Answer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// Response is a parsed DNS response.
type Response struct {
	RCode   dnsmessage.RCode
	Answers []Answer
	UsedTCP bool
	Server  string
}

// RCodeError means the resolver answered but reported a failure, for example
// SERVFAIL or REFUSED. The resolver itself was reachable.
type RCodeError struct{ RCode dnsmessage.RCode }

func (e *RCodeError) Error() string {
	switch e.RCode {
	case dnsmessage.RCodeServerFailure:
		return "the resolver reported a server failure (SERVFAIL)"
	case dnsmessage.RCodeRefused:
		return "the resolver refused the lookup (REFUSED)"
	case dnsmessage.RCodeFormatError:
		return "the resolver did not understand the lookup (FORMERR)"
	case dnsmessage.RCodeNotImplemented:
		return "the resolver does not support this lookup (NOTIMP)"
	}
	return fmt.Sprintf("the resolver returned error code %d", uint16(e.RCode))
}

var errNoAnswer = errors.New("no answer in time")

// tcpRetryError means the UDP answer was truncated and asking again over TCP
// failed, for example because a firewall blocks DNS over TCP.
type tcpRetryError struct{ err error }

func (e *tcpRetryError) Error() string {
	return "the answer was too big for UDP and the TCP retry failed: " + e.err.Error()
}

func (e *tcpRetryError) Unwrap() error { return e.err }

// Client sends DNS queries over UDP, falling back to TCP when an answer is
// truncated. A shared semaphore caps how many queries are in flight across
// the whole run, no matter how many goroutines call Query.
type Client struct {
	Timeout time.Duration
	sem     chan struct{}

	mu     sync.Mutex
	health map[string]*resolverHealth // keyed by resolver addresses
}

// NewClient returns a client that waits up to timeout for each answer and
// keeps at most maxInFlight queries open at once.
func NewClient(timeout time.Duration, maxInFlight int) *Client {
	if maxInFlight < 1 {
		maxInFlight = 1
	}
	return &Client{Timeout: timeout, sem: make(chan struct{}, maxInFlight)}
}

// Query asks resolver r for records of type qtype at name. NXDOMAIN is not an
// error: it returns a response with no answers. Other failure codes return an
// *RCodeError. Network problems return the network error.
func (c *Client) Query(ctx context.Context, r Resolver, name string, qtype dnsmessage.Type) (*Response, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()

	q, err := newQuestion(name, qtype)
	if err != nil {
		return nil, err
	}
	lastErr := errors.New("the resolver has no address")
	for _, addr := range r.Addrs {
		resp, err := c.exchange(ctx, addr, q)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func newQuestion(name string, t dnsmessage.Type) (dnsmessage.Question, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Question{}, fmt.Errorf("bad name %q: %w", name, err)
	}
	return dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}, nil
}

func buildQuery(id uint16, q dnsmessage.Question) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

func (c *Client) exchange(ctx context.Context, addr string, q dnsmessage.Question) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	id := uint16(rand.UintN(1 << 16))
	msg, err := buildQuery(id, q)
	if err != nil {
		return nil, err
	}
	raw, err := exchangeUDP(ctx, addr, msg, id, q, c.Timeout)
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		return nil, fmt.Errorf("could not read the answer: %w", err)
	}
	usedTCP := false
	if h.Truncated {
		raw, err = exchangeTCP(ctx, addr, msg, id, q)
		if err != nil {
			return nil, &tcpRetryError{err: err}
		}
		usedTCP = true
	}
	resp, err := parseResponse(raw)
	if err != nil {
		return nil, err
	}
	resp.UsedTCP = usedTCP
	resp.Server = addr
	if resp.RCode != dnsmessage.RCodeSuccess && resp.RCode != dnsmessage.RCodeNameError {
		return nil, &RCodeError{RCode: resp.RCode}
	}
	return resp, nil
}

// exchangeUDP sends the query and waits for the matching answer. Packets can
// be lost, so the query is sent a second time halfway through the timeout.
func exchangeUDP(ctx context.Context, addr string, msg []byte, id uint16, q dnsmessage.Question, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	buf := make([]byte, 65535)
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return nil, errNoAnswer
		}
		wait := deadline
		if attempt == 0 {
			if half := time.Now().Add(timeout / 2); half.Before(deadline) {
				wait = half
			}
		}
		if err := conn.SetReadDeadline(wait); err != nil {
			return nil, err
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil, errNoAnswer
				}
				if isTimeout(err) {
					break
				}
				return nil, err
			}
			if matches(buf[:n], id, q) {
				return append([]byte(nil), buf[:n]...), nil
			}
			// Not our answer (late reply to an earlier attempt, or junk). Keep waiting.
		}
	}
	return nil, errNoAnswer
}

// exchangeTCP sends the query over TCP with the two-byte length prefix.
func exchangeTCP(ctx context.Context, addr string, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	if !matches(body, id, q) {
		return nil, errors.New("the TCP answer did not match the question")
	}
	return body, nil
}

// matches reports whether raw is a response to our query: same ID, marked as
// a response, and echoing the same question.
func matches(raw []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil || h.ID != id || !h.Response {
		return false
	}
	got, err := p.Question()
	if err != nil {
		// Some servers drop the question from error answers.
		return errors.Is(err, dnsmessage.ErrSectionDone) && h.RCode != dnsmessage.RCodeSuccess
	}
	return got.Type == q.Type && strings.EqualFold(got.Name.String(), q.Name.String())
}

// parseResponse reads the answer section into plain strings.
func parseResponse(raw []byte) (*Response, error) {
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		return nil, fmt.Errorf("could not read the answer: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("could not read the answer: %w", err)
	}
	resp := &Response{RCode: h.RCode}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("could not read the answer: %w", err)
		}
		value, ok, err := readValue(&p, rh.Type)
		if err != nil {
			return nil, fmt.Errorf("could not read a %s record: %w", typeName(rh.Type), err)
		}
		if !ok {
			continue
		}
		resp.Answers = append(resp.Answers, Answer{
			Name:  cleanName(rh.Name),
			Type:  typeName(rh.Type),
			Value: value,
			TTL:   rh.TTL,
		})
	}
	return resp, nil
}

// readValue turns one record body into its text form. ok is false for record
// types this tool does not use; those are skipped.
func readValue(p *dnsmessage.Parser, t dnsmessage.Type) (string, bool, error) {
	switch t {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		return netip.AddrFrom4(r.A).String(), err == nil, err
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		return netip.AddrFrom16(r.AAAA).String(), err == nil, err
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		return cleanName(r.NS), err == nil, err
	case dnsmessage.TypeCNAME:
		r, err := p.CNAMEResource()
		return cleanName(r.CNAME), err == nil, err
	case dnsmessage.TypeSOA:
		r, err := p.SOAResource()
		v := fmt.Sprintf("%s %s %d %d %d %d %d", cleanName(r.NS), cleanName(r.MBox), r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
		return v, err == nil, err
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		return fmt.Sprintf("%d %s", r.Pref, cleanName(r.MX)), err == nil, err
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		// A TXT record can be split into several strings; SPF and DKIM
		// join them with nothing in between (RFC 7208 section 3.3).
		return strings.Join(r.TXT, ""), err == nil, err
	case typeCAA:
		r, err := p.UnknownResource()
		if err != nil {
			return "", false, err
		}
		v, err := decodeCAA(r.Data)
		return v, err == nil, err
	case typeDS:
		r, err := p.UnknownResource()
		if err != nil {
			return "", false, err
		}
		v, err := decodeDS(r.Data)
		return v, err == nil, err
	}
	return "", false, p.SkipAnswer()
}

// cleanName lowercases a name and drops the trailing dot. The root name
// becomes ".".
func cleanName(n dnsmessage.Name) string {
	s := strings.TrimSuffix(strings.ToLower(n.String()), ".")
	if s == "" {
		return "."
	}
	return s
}

// decodeCAA reads a CAA record (RFC 8659): flags, tag length, tag, value.
func decodeCAA(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("CAA record too short")
	}
	tagLen := int(data[1])
	if 2+tagLen > len(data) {
		return "", errors.New("CAA tag longer than the record")
	}
	tag := strings.ToLower(string(data[2 : 2+tagLen]))
	value := string(data[2+tagLen:])
	return fmt.Sprintf("%d %s %q", data[0], tag, value), nil
}

// decodeDS reads a DS record (RFC 4034): key tag, algorithm, digest type, digest.
func decodeDS(data []byte) (string, error) {
	if len(data) < 4 {
		return "", errors.New("DS record too short")
	}
	keyTag := binary.BigEndian.Uint16(data[0:2])
	return fmt.Sprintf("%d %d %d %s", keyTag, data[2], data[3], strings.ToUpper(hex.EncodeToString(data[4:]))), nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// plainError turns a lookup error into short, plain words.
func plainError(err error) string {
	var rc *RCodeError
	var tcp *tcpRetryError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &tcp):
		return "the answer was too big for UDP and the TCP retry failed (" + plainError(tcp.err) + ")"
	case errors.As(err, &rc):
		return rc.Error()
	case errors.Is(err, errSkipped):
		return errSkipped.Error()
	case errors.Is(err, errNoAnswer), errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "no answer in time"
	case errors.Is(err, context.Canceled):
		return "stopped before an answer came back"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed before an answer came back"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable"
	}
	return err.Error()
}
