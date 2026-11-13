# dns-check

dns-check looks at a domain's DNS and email setup and tells you, in plain
words, what is set up well and what needs fixing. It asks several DNS
resolvers at the same time and compares their answers, so it also spots
changes that have not reached everyone yet.

It ends with a short list of fixes in priority order and one clear answer to
the question most business owners actually care about:

> Could someone send email that looks like it comes from this domain?

## What it checks, and why it matters

**Website**
- The domain's address (A) and IPv6 address (AAAA). If the bare domain points
  nowhere, typing it without www shows an error.
- `www` (CNAME and A). People type both. A www record that points at a name
  with no address (an old host you left) is flagged. A CNAME chain is shown in
  order. For a subdomain (a name with no name servers of its own, such as
  shop.example.com) the www check is skipped.

**Name servers**
- NS and SOA. With only one name server, the whole domain goes dark if it fails.

**Email delivery**
- MX records. With none, email sent to your domain has nowhere to go. A
  "null MX" (the domain says it never receives email) is recognised.

**Email security**
- **SPF**, the list of servers allowed to send your email. Flags: missing,
  more than one SPF record (that breaks SPF entirely), ending in `+all` (anyone
  may send as you), `?all` (says nothing), no `all` rule at all, and `~all`
  versus `-all`. Receivers stop reading at the first `all`, so anything after
  it is ignored; that is flagged too. It counts the DNS lookups the record
  needs, following `include:` and `redirect=` into other domains (up to 10
  levels deep). Over 10 lookups, or an include that points at a domain with no
  SPF record (or more than one), receivers treat SPF as broken, and the report
  says so.
- **DMARC**, the rule that tells receivers what to do with email that fails the
  checks. Flags: missing, `p=none` (monitoring only, fakes still delivered),
  `p=quarantine` (fakes go to spam), `p=reject` (fakes refused), `pct` below
  100, `sp=none`, and whether reports (`rua=`) are being collected. When a
  subdomain has no DMARC record of its own, the nearest parent domain's record
  applies (its `sp=` policy, or `p=` when there is no `sp=`), and the report
  says where the policy came from.
- **DKIM**, the signature on your outgoing email. It looks for keys at these
  common selector names: default, selector1, selector2, google, k1, s1, s2,
  dkim, mail, smtp, mxvault, protonmail, zoho, resend. Use `-selectors` to try
  your own.
- **MTA-STS** (`_mta-sts`) and **TLS reporting** (`_smtp._tls`), which keep
  email to you encrypted in transit and tell you when that fails.
- **BIMI** (`default._bimi`), which lets some inboxes show your logo.

**Domain security**
- **CAA**: which certificate authorities may issue certificates for the domain.
  A subdomain without CAA records of its own is covered by its parent's.
- **DNSSEC**: whether the domain is signed (a DS record exists at the registry).
  A subdomain without name servers of its own shares the DNSSEC of the zone it
  lives in. When the domain is signed but most resolvers answer with an error
  (SERVFAIL) for it, the report says DNSSEC looks broken. Resolvers that check
  DNSSEC do that when they cannot verify the zone's answers, for example when
  the DS record at the registrar no longer matches the zone's keys.

**Resolvers**
- By default it asks your computer's own resolver plus Cloudflare (1.1.1.1),
  Google (8.8.8.8) and Quad9 (9.9.9.9). When they give different answers, it
  says which resolver saw what. That usually means a recent change is still
  spreading. Different website addresses on their own are only a note,
  because content delivery networks (CDNs) do that on purpose.
- If a resolver cannot be reached, the report says so and the check carries
  on with the others.
- If some resolvers say the domain does not exist while others see it, the
  report says which resolver sees what (a new or moved domain is usually still
  spreading) and uses the answers from the resolvers that see it.
- If no resolver gives a usable answer for a key record (SOA, NS, MX, the TXT
  record that holds SPF, or DMARC), that is a warning. So a "Not sure"
  spoofing answer never comes with exit code 0.
- Differences in the SOA serial number alone are ignored. Many DNS providers
  change it on every edit.

**The spoofing answer**

The question is about the From line people see in their inbox. Only DMARC
tells receivers to check that line. SPF on its own checks a hidden sender
address that a faker can set to any domain they own, so SPF alone does not
stop a fake From line.

- **Unlikely**: DMARC is set to reject or quarantine for all email, and SPF
  does not end in `+all`.
- **Partly**: DMARC enforcement covers only part of the email (`pct` below
  100).
- **Yes**: SPF ends in `+all`, or DMARC is missing, not valid, or only
  monitoring (`p=none`), whatever SPF says.
- **Not sure**: only when the SPF or DMARC lookups failed on every resolver,
  or the domain does not exist in DNS.

## Install

```
go install github.com/RavGB/dns-check@latest
```

The module targets Go 1.25 or newer. It was built and tested with Go 1.27.

## Usage

```
dns-check example.com
dns-check -v example.com                  # also show how to fix each finding and every record
dns-check -json example.com > report.json # machine-readable output
dns-check -resolvers 1.1.1.1,8.8.8.8 -selectors s1,s2 example.com
dns-check -f domains.txt                  # one domain per line, "#" starts a comment
```

You can pass a bare domain, a URL (`https://www.example.com/contact`) or an
email address (`hello@example.com`); it keeps just the domain part. A leading
`www.` is left off, because email and DNS settings belong to the domain
itself, and the report says so; the www address is still checked as part of
the domain. So `https://www.example.com/contact` checks `example.com`. Names in
other scripts, such as `bücher.example`, are checked in their `xn--` form. An
IP address is refused, because there is no domain to check. Flags can go
before or after the domains.

Flags:

| Flag | Meaning |
| --- | --- |
| `-f file` | read domains from a file, one per line (`-` reads standard input) |
| `-json` | print JSON instead of the plain-text report |
| `-resolvers list` | comma separated `ip` or `ip:port`; `system` means your computer's resolver from `/etc/resolv.conf` (default `system,1.1.1.1,8.8.8.8,9.9.9.9`) |
| `-selectors list` | comma separated DKIM selector names to try (default: the list above) |
| `-timeout time` | how long to wait for each answer (default `3s`) |
| `-concurrency n` | most lookups in flight at once (default `16`) |
| `-v` | also show how to fix each finding and list every record, with each resolver's answer where they differ or failed |
| `-version` | print the version |
| `-h` | show help |

## Sample output

This is a real run against example.com, the domain reserved for documentation,
on 2026-11-13, copied as printed. It asks only the three public resolvers, so
no private resolver address appears:

```
$ dns-check -resolvers 1.1.1.1,8.8.8.8,9.9.9.9 example.com
DNS and email check for example.com
Checked 2026-11-13 18:59 UTC with 3 resolvers: Cloudflare (1.1.1.1), Google
(8.8.8.8) and Quad9 (9.9.9.9).
Summary: 0 problems, 0 warnings, 4 notes, 8 things look good.

Website
  [ok]      example.com points to 104.20.23.154 and 172.66.147.243, and to
            2606:4700:10::6814:179a and 2606:4700:10::ac42:93f3 over IPv6.
  [ok]      www.example.com works. It points to 104.20.23.154 and
            172.66.147.243.

Name servers
  [ok]      2 name servers: elliott.ns.cloudflare.com and hera.ns.cloudflare.com
            (looks like Cloudflare).

Email delivery
  [ok]      example.com says it does not accept email (a null MX record). That
            is right if the domain never receives email.

Email security
  [ok]      SPF is set up and ends in -all, so email from servers not on the
            list should be rejected. It uses 0 of the 10 allowed DNS lookups.
            Record: v=spf1 -all
  [ok]      DMARC is set to p=reject, so email that fails the checks should be
            refused.
  [note]    DMARC has no reporting address (rua=), so nobody receives the
            reports about who sends email using this domain.
  [note]    All 14 DKIM selector names checked return an empty key. That is how
            a domain says it does not sign email, which is normal if it sends no
            email.
  [note]    No BIMI record. With DMARC already enforcing, BIMI lets some inboxes
            show your logo next to your email.

Domain security
  [note]    No CAA record, so any certificate authority may issue a certificate
            for example.com.
  [ok]      DNSSEC is on (a DS record is published at the registry), so
            resolvers can detect forged DNS answers for this domain.

Resolvers
  [ok]      All 3 resolvers gave the same answers.

Could someone send email that looks like it comes from example.com?
  Unlikely: DMARC is set to reject, so receiving mail servers are told to refuse
  email that fails the SPF and DKIM checks.

Top fixes
  Nothing urgent.
  Optional improvements:
  1. Add rua=mailto:<a mailbox you read> to the DMARC record to get daily
     reports about who sends email using your domain.
  2. Add a CAA record naming the certificate authority you use, for example 0
     issue "letsencrypt.org" if your certificates come from Let's Encrypt.
  3. Publish a BIMI record at default._bimi.example.com pointing to your logo in
     SVG format.

dns-check 0.1.0 by RavGB, https://ravgb.com
```

That run exited with code 1, because DMARC at `p=none` is a warning.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The check finished and found nothing at warning level or above. Notes alone do not change the exit code. |
| `1` | The check finished and found at least one warning or problem. |
| `2` | Usage error (bad flag, bad domain, bad resolver address, unreadable `-f` file) or a fatal error, such as no resolver answering at all. |

With several domains, the highest code wins.

## JSON output

`-json` prints one object with `tool`, `version`, `exit_code`, `notes` and
`results`. Each result has the `domain` and either an `error` or a `report`.
A report holds every record with each resolver's answer (`per_resolver`), the
answer most resolvers gave (`values`), whether they agreed, the SPF and DMARC
details (for DMARC, `found_at` says where the record is and `applied_policy`
the policy that applies to this domain), the DKIM selectors found, every
finding (`severity` is one of `ok`, `note`, `warning`, `problem`, plus a
stable `code` such as `spf_plus_all`), the spoofing answer, and the fixes.
`input_note` says when the input was changed (for example a `www.` left off),
and `not_seen_by` lists resolvers that said the domain does not exist while
others saw it.

## How it works

- Every lookup is a DNS query built with `golang.org/x/net/dns/dnsmessage` and
  sent over UDP (with EDNS0, 1232-byte answers), resent once if no answer
  comes back, and retried over TCP when the answer is truncated. That is how it
  can ask for CAA, DS and SOA records, which the Go standard library resolver
  cannot look up.
- All (resolver x record) lookups run in parallel goroutines, capped by
  `-concurrency`. SPF includes are followed level by level, each level in
  parallel. Each lookup has its own timeout.
- The analysis uses the answer most resolvers gave. A resolver that fails three
  times without a single answer is skipped for the rest of the run.
- It only talks DNS. It makes no HTTP requests.

The only dependencies outside the Go standard library are `golang.org/x/net`,
used for its `dns/dnsmessage` and `idna` packages, and `golang.org/x/text`,
which `idna` uses.

## What it does not check

- It does not fetch the MTA-STS policy file, the BIMI logo, or any web page.
- It does not validate DNSSEC signatures itself. It reports whether a DS
  record exists.
- It does not check DKIM key strength, send test email, or test whether your
  mail servers accept email or offer valid encryption.
- It only finds DKIM keys at the selector names it tries.
- It checks the name you give, apart from a leading `www.`. For a subdomain,
  it looks for the parent's DMARC, CAA and DNSSEC as described above, going up
  to names with two labels. It does not use the full Public Suffix List: it
  skips common shared suffixes such as `co.uk`, `com.au` or `on.ca`, but an
  unusual shared suffix could be treated as a parent domain.
- It counts the SPF terms that cost a DNS lookup. It does not evaluate SPF for
  a particular sending server, and it does not count the extra address lookups
  inside `mx` and `ptr` or "void" lookups.
- It does not check reverse DNS (PTR) for your mail servers or email blocklists.
- The system resolver is read from `/etc/resolv.conf`. Where that file does not
  exist (for example on Windows), the system resolver is skipped with a note
  and the public resolvers are used.

## Made by RavGB

Made by RavGB, https://ravgb.com. RavGB helps small SaaS teams with DevOps on
AWS, websites, promotional video and custom tools. A free website check (speed,
accessibility, search basics, how it works on a phone) and a free AWS audit are
available at https://ravgb.com.

Licensed under the MIT License. See [LICENSE](LICENSE).
