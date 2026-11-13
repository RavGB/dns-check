package main

import (
	"strconv"
	"strings"
)

// parseTags reads "k=v; k=v" records (DMARC, DKIM, MTA-STS, TLS-RPT, BIMI).
// Keys are lowercased; values are trimmed.
func parseTags(s string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := tags[k]; dup || k == "" {
			continue
		}
		tags[k] = strings.TrimSpace(v)
	}
	return tags
}

// hasVersion reports whether a tag record starts with v=<want>.
func hasVersion(s, want string) bool {
	first, _, _ := strings.Cut(s, ";")
	k, v, ok := strings.Cut(first, "=")
	return ok && strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), want)
}

func isDMARC(s string) bool { return hasVersion(s, "DMARC1") }

// dmarcRecord is a parsed DMARC record (RFC 7489).
type dmarcRecord struct {
	Raw       string
	Policy    string // none, quarantine, reject, or "" when missing or not valid
	SubPolicy string
	Pct       int
	RUA       []string
}

func parseDMARC(raw string) dmarcRecord {
	tags := parseTags(raw)
	d := dmarcRecord{Raw: raw, Pct: 100}
	switch p := strings.ToLower(tags["p"]); p {
	case "none", "quarantine", "reject":
		d.Policy = p
	}
	switch sp := strings.ToLower(tags["sp"]); sp {
	case "none", "quarantine", "reject":
		d.SubPolicy = sp
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil && n >= 0 && n <= 100 {
			d.Pct = n
		}
	}
	for _, u := range strings.Split(tags["rua"], ",") {
		u = strings.TrimSpace(u)
		if len(u) >= 7 && strings.EqualFold(u[:7], "mailto:") {
			u = u[7:]
		}
		if u != "" {
			d.RUA = append(d.RUA, u)
		}
	}
	return d
}

// dkimKey describes what was found at one DKIM selector.
type dkimKey struct {
	Found   bool // a DKIM record is there
	Revoked bool // the record has an empty p= (key withdrawn)
}

func readDKIM(values []string) dkimKey {
	for _, v := range values {
		tags := parseTags(v)
		p, hasP := tags["p"]
		if !hasP && !hasVersion(v, "DKIM1") {
			continue
		}
		if p == "" {
			return dkimKey{Found: true, Revoked: true}
		}
		return dkimKey{Found: true}
	}
	return dkimKey{}
}

// provider guesses who runs a host from its name. Only a hint. When
// contains is set, match may appear anywhere in the host name; otherwise the
// host must equal match or end with "."+match.
type provider struct {
	match, name string
	contains    bool
}

var mxProviders = []provider{
	{"google.com", "Google Workspace", false},
	{"googlemail.com", "Google Workspace", false},
	{"mail.protection.outlook.com", "Microsoft 365", false},
	{"zoho.com", "Zoho Mail", false},
	{"zoho.eu", "Zoho Mail", false},
	{"zoho.in", "Zoho Mail", false},
	{"protonmail.ch", "Proton Mail", false},
	{"messagingengine.com", "Fastmail", false},
	{"mx.cloudflare.net", "Cloudflare Email Routing", false},
	{"secureserver.net", "GoDaddy", false},
	{"privateemail.com", "Namecheap Private Email", false},
	{"improvmx.com", "ImprovMX", false},
	{"mailgun.org", "Mailgun", false},
	{"amazonaws.com", "Amazon SES or WorkMail", false},
	{"icloud.com", "iCloud Mail", false},
}

var nsProviders = []provider{
	{"ns.cloudflare.com", "Cloudflare", false},
	{"vercel-dns.com", "Vercel", false},
	{"domaincontrol.com", "GoDaddy", false},
	{"googledomains.com", "Google Cloud DNS", false},
	{"registrar-servers.com", "Namecheap", false},
	{"nsone.net", "NS1", false},
	{"digitalocean.com", "DigitalOcean", false},
	{"wixdns.net", "Wix", false},
	{"ns.porkbun.com", "Porkbun", false},
	{"dnsimple.com", "DNSimple", false},
	{"ovh.net", "OVHcloud", false},
	{".awsdns-", "Amazon Route 53", true},
	{".azure-dns.", "Azure DNS", true},
}

// guessProvider returns the provider name when every host matches the same one.
func guessProvider(hosts []string, list []provider) string {
	found := ""
	for _, h := range hosts {
		name := ""
		for _, p := range list {
			if (p.contains && strings.Contains(h, p.match)) ||
				(!p.contains && (h == p.match || strings.HasSuffix(h, "."+p.match))) {
				name = p.name
				break
			}
		}
		if name == "" || (found != "" && found != name) {
			return ""
		}
		found = name
	}
	return found
}
