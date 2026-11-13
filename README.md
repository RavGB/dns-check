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
  with no address (an old host you left) is flagged.

**Name servers**
- NS and SOA. With only one name server, the whole domain goes dark if it fails.

**Email delivery**
- MX records. With none, email sent to your domain has nowhere to go. A
  "null MX" (the domain says it never receives email) is recognised.

**Email security**
- **SPF**, the list of servers allowed to send your email. Flags: missing,
  more than one SPF record (that breaks SPF entirely), ending in `+all` (anyone
  may send as you), `?all` (says nothing), no `all` rule at all, and `~all`
  versus `-all`. It also counts the DNS lookups the record needs, following
  `include:` and `redirect=` into other domains (up to 10 levels deep). Over 10
  lookups, receivers may treat SPF as broken. Includes that point at a domain
  with no SPF record are flagged too.
- **DMARC**, the rule that tells receivers what to do with email that fails the
  checks. Flags: missing, `p=none` (monitoring only, fakes still delivered),
  `p=quarantine` (fakes go to spam), `p=reject` (fakes refused), `pct` below
  100, `sp=none`, and whether reports (`rua=`) are being collected.
- **DKIM**, the signature on your outgoing email. It looks for keys at these
  common selector names: default, selector1, selector2, google, k1, s1, s2,
  dkim, mail, smtp, mxvault, protonmail, zoho, resend. Use `-selectors` to try
  your own.
- **MTA-STS** (`_mta-sts`) and **TLS reporting** (`_smtp._tls`), which keep
  email to you encrypted in transit and tell you when that fails.
- **BIMI** (`default._bimi`), which lets some inboxes show your logo.

**Domain security**
- **CAA**: which certificate authorities may issue certificates for the domain.
- **DNSSEC**: whether the domain is signed (a DS record exists at the registry).

**Resolvers**
- By default it asks your computer's own resolver plus Cloudflare (1.1.1.1),
  Google (8.8.8.8) and Quad9 (9.9.9.9). When they give different answers, it
  says which resolver saw what. That usually means a recent change is still
  spreading. Different website addresses on their own are only a note,
  because content delivery networks (CDNs) do that on purpose.
- If a resolver cannot be reached, the report says so and the check carries
  on with the others.

**The spoofing answer**
- **Unlikely**: DMARC is set to reject or quarantine for all email, and SPF
  does not end in `+all`.
- **Partly**: DMARC enforcement covers only part of the email (`pct` below
  100), or SPF is set up but DMARC is missing or only monitoring.
- **Yes**: SPF ends in `+all`, or there is neither a working SPF record nor an
  enforcing DMARC policy.
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
email address (`hello@example.com`); it keeps just the domain part.

Flags:

| Flag | Meaning |
| --- | --- |
| `-f file` | read domains from a file, one per line (`-` reads standard input) |
| `-json` | print JSON instead of the plain-text report |
| `-resolvers list` | comma separated `ip` or `ip:port`; `system` means your computer's resolver from `/etc/resolv.conf` (default `system,1.1.1.1,8.8.8.8,9.9.9.9`) |
| `-selectors list` | comma separated DKIM selector names to try (default: the list above) |
| `-timeout time` | how long to wait for each answer (default `3s`) |
| `-concurrency n` | most lookups in flight at once (default `16`) |
| `-v` | also show how to fix each finding and list every record with each resolver's answer |
| `-version` | print the version |
| `-h` | show help |

## Sample output

This is a real run against ravgb.com on 2026-11-13, copied as printed:

```
$ dns-check ravgb.com
DNS and email check for ravgb.com
Checked 2026-11-13 18:14 UTC with 4 resolvers: System resolver
(2001:4e8:0:4001::17), Cloudflare (1.1.1.1), Google (8.8.8.8) and Quad9
(9.9.9.9).
Summary: 0 problems, 1 warning, 5 notes, 7 things look good.

Website
  [ok]      ravgb.com points to 104.21.16.6 and 172.67.165.163, and to
            2606:4700:3030::ac43:a5a3 and 2606:4700:3033::6815:1006 over IPv6.
  [ok]      www.ravgb.com works. It points to 104.21.16.6 and 172.67.165.163.

Name servers
  [ok]      2 name servers: isaac.ns.cloudflare.com and vida.ns.cloudflare.com
            (looks like Cloudflare).

Email delivery
  [ok]      Email for ravgb.com is delivered to sunfire.mxrouting.net and
            sunfire-relay.mxrouting.net.

Email security
  [warning] DMARC is set to p=none, which is monitoring only. Receivers may
            report fakes to you, but they are still told to deliver them.
  [ok]      SPF is set up and ends in -all, so email from servers not on the
            list should be rejected. It uses 4 of the 10 allowed DNS lookups.
            Record: v=spf1 include:mxroute.com -all
  [note]    DMARC has no reporting address (rua=), so nobody receives the
            reports about who sends email using this domain.
  [ok]      A DKIM signing key was found at selector resend.
  [note]    No MTA-STS record. MTA-STS asks other mail servers to always use an
            encrypted connection when they deliver email to you.
  [note]    No TLS reporting record (TLS-RPT), so nobody is told when other
            servers fail to deliver email to you over an encrypted connection.

Domain security
  [note]    No CAA record, so any certificate authority may issue a certificate
            for ravgb.com.
  [note]    DNSSEC is off. DNSSEC lets resolvers detect forged DNS answers for
            this domain.

Resolvers
  [ok]      All 4 resolvers that answered gave the same answers.

Could someone send email that looks like it comes from ravgb.com?
  Partly: SPF catches some fakes, but DMARC is set to monitoring only (p=none),
  so nothing stops a fake that shows ravgb.com in the From line people see.

Top fixes
  1. Add rua=mailto:<a mailbox you read> to the DMARC record so you get reports,
     then, once they show all your real email passes, change p=none to
     p=quarantine and then p=reject.

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
details, the DKIM selectors found, every finding (`severity` is one of `ok`,
`note`, `warning`, `problem`, plus a stable `code` such as `spf_plus_all`),
the spoofing answer, and the fixes.

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

The only dependency outside the Go standard library is `golang.org/x/net`,
used for its `dns/dnsmessage` package.

## What it does not check

- It does not fetch the MTA-STS policy file, the BIMI logo, or any web page.
- It does not validate DNSSEC signatures itself. It reports whether a DS
  record exists.
- It does not check DKIM key strength, send test email, or test whether your
  mail servers accept email or offer valid encryption.
- It only finds DKIM keys at the selector names it tries.
- It checks the exact name you give. For a subdomain, it does not look up the
  DMARC policy or CAA records the parent domain may pass down.
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
