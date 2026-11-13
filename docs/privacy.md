# Privacy and network traffic

← [README](../README.md)

## What leaves the host

- **Matching is local.** Cornicen downloads whole public datasets (CVE List, KEV, EPSS bulk). These bulk requests send no product name, version or CVE ID to a data source.
- **Notifications carry your data to the channel you configure.** An alert names the product and version it matched. If your ntfy server is someone else's, they see that. Self-host ntfy for end-to-end privacy.
- **Dead-man pings are opt-in.** `CORNICEN_DEADMAN_URL` or `CORNICEN_DEADMAN_URL_FILE` enables a GET to your monitor after completed cycles, at most once per `deadman_interval_minutes` (default 5). It sends no product, version, watch or CVE data: no body or added query, and User-Agent `Cornicen` without a version. The monitor sees your network address and ping timing. The URL is a secret, redacted alongside tokens and excluded from status, health details and logs. Redaction includes fragment-free, percent-decoded and encoded forms, userinfo, host, path, query, and path segments and query values of at least six characters; longer forms are removed first. Keep it outside TOML.
- **No telemetry, analytics or Cornicen self-update check.** This page lists every host contacted by default.
- **Latest-release checks are opt-in per watch.** Only a watch with `latest_release = "github:example-org/widget"` enables a daily request to `api.github.com/repos/example-org/widget/releases/latest`. There is no default list; without the field nothing is checked. The request carries the repository path only, never the watched version. This reveals the upstream repository of software you run to GitHub. With the optional GitHub token, these checks are tied to the operator's GitHub account, not only an IP address. GitHub advisories and per-CVE lookups remain unshipped.
- Runs as non-root, read-only root filesystem, writable volume only for SQLite, watch list mounted read-only. No inbound port. The ntfy token comes from an environment variable or file; the optional GitHub token comes from a file only. Neither token belongs in the shareable TOML.
- User-Agent configurable, default `Cornicen/<version> (+<repo URL>)`.

Default source traffic goes to `github.com`, `api.github.com`,
`objects.githubusercontent.com`, and `release-assets.githubusercontent.com` for CVE List releases; `www.cisa.gov` for KEV;
and `epss.empiricalsecurity.com` for EPSS. Notifications go to your ntfy server
(the config loader defaults to `ntfy.sh`; the example requires you to set a
server). Every public-source request, redirect, pagination link and asset URL
must use HTTPS on port 443 and stay within that source's hosts listed above.
Userinfo and IP literals are rejected. DNS answers are checked at connection
time; loopback, private, link-local, unique-local, multicast and other non-public
addresses are rejected. Connections use the checked address directly while TLS
verifies the original hostname. Public sources ignore environment HTTP proxies.
The configured ntfy destination is separate from these source allowlists.
Notification redirects are rejected, so Authorization is never forwarded.
The optional dead-man destination is also separate from source allowlists and
may use HTTP or HTTPS. Its requests use a 10-second socket timeout, reject redirects
to a different host and HTTPS downgrades, and do not retry within the interval.
A daemon worker runs at most one ping; the scheduler records results on a later
tick and records failure when it observes 30 seconds elapsed. A stalled request
cannot delay the loop or shutdown, and prevents overlapping requests until it exits.
Worker exceptions are discarded; only fixed outcome details are persisted.
Latest-release checks use the same GitHub client, token, persistent ETags and
rate budget as CVE List requests. There are no other scheduled service calls.

EPSS refetches its public bulk file hourly until today's UTC score date is
stored, then waits until the next UTC day. Each transfer retains the same
redirect, destination and download-budget checks.

Compressed download budgets are 2 GiB / 45 minutes for a CVE List snapshot,
200 MiB / 5 minutes for a CVE List delta, 20 MiB / 5 minutes for KEV, and
64 MiB / 5 minutes for EPSS. These are `DOWNLOAD_BUDGETS` in
`src/cornicen/config.py`; positive integer overrides use TOML tables such as:

```toml
[download_budgets.cvelist_snapshot]
max_bytes = 2147483648
deadline_seconds = 2700
```

Other budget table names are `cvelist_delta`, `kev`, and `epss`. The total
deadline spans redirects and body transfer, alongside 60-second socket timeouts.
Exceeding a budget fails the fetch and removes its partial download. EPSS also
limits expanded input to 256 MiB and 2,000,000 rows, with CVE identifiers at most
32 characters matching `CVE-\d{4}-\d{4,19}` (ASCII digits). Rejected feeds preserve
the accepted scores.

With the optional GitHub token, GitHub sees CVE List fetches as coming from that
account rather than an anonymous IP. The token goes only to `api.github.com`.
Bulk CVE requests are the same public release listings and archives either way.
Opt-in latest-release checks additionally disclose the configured repository paths. Archive download hosts never receive the token.

The minute log line's `report` and `github` blocks contain only aggregate counts,
an auth status word and integers (or null when unavailable). They contain no watch
IDs, names, vendor/product strings, CVE IDs or diagnostic free text.

Latest-release tags are upstream text. They may appear in digest bodies, but
never in stdout, heartbeat, status or health detail. The `releases` health
component uses fixed words and aggregate counts only; failures do not change
CVE source health. Status reports the number of enabled watches, never their
repositories.

## Command failure diagnostics

Untrusted text in every `command failed: <Type>: <message>` line passes through
`public_text`, using loaded watches as private inventory when available. Fixed
roles, reasons and integer positions are built separately and remain visible even
when inventory or a secret happens to equal a diagnostic word. File failures name
the role (config, watch list, aliases_path, acceptance list, acceptance watch
list or token file), never the path or file contents. Invalid TOML includes
line and column when the parser supplies a position, including end of file.
Recursion failures have no parser position. Watch and accept failures name
the entry index; unknown keys and duplicate IDs are withheld.

Unknown configuration keys include only a count and a fixed hint to compare
with docs/cli.md. Names are never shown, including vocabulary words and numbers.
Token-file permission errors name the environment variable and require owner-only
mode 0600 or the existing shared-file opt-out. Backup failures identify the
database file or backup destination without paths or OS prose.

Only an actual `FixedDiagnostic` carries fixed provenance, including acceptance
public messages and nested validation reasons. Unmarked nested errors become
`invalid value`; exception classes and plain-text attributes confer no trust.

`watch validation error:` lines from `watch check` retain valid watch IDs
for locating entries, but omit acceptance CVEs, paths, unknown keys and invalid
constraint text. Every validation line redacts known ntfy and GitHub secrets,
including a watch ID that equals a secret. Inventory output from status, report and explain remains operator-only.

## Webhook destination

`notifier = "webhook"` replaces the ntfy channel with an outbound HTTPS POST to
one host the operator chooses. That receiver sees the alert's inventory, CVE
IDs, your network address and notification timing. It may be self-hosted. This
is separate from public-source host restrictions. Redirects are never followed.
The URL and signing secret come only from environment values or private files,
never TOML, and are excluded from status, health details, heartbeats and command
failure lines. Both join the redaction set, including percent-decoded and encoded
URL forms, Unicode/IDNA hosts, paths and query strings. Individual path segments
and query values are redacted only when their decoded length is at least six
characters. Short standalone components such as `x1`, `api` and `1` are intentionally
left intact so credentials cannot rewrite ordinary counts and fixed diagnostics.
Use long random credentials. Full configured secrets and complete URLs are always
redacted, regardless of length. Equivalent percent-escape hex casing is covered.
The webhook payload carries the same rendered notification text as ntfy. Cornicen
never copies a configured credential into a notification, but neither channel
filters third-party CVE text: a CNA title or description that happens to quote a
string identical to one of your credentials is delivered as written. That can
only repeat a value the record's author already had.
HMAC authenticates raw request bytes; HTTPS protects them in transit. A native
service may ignore HMAC headers; use a verifying bridge when required.
Email forwarding belongs to the ntfy server; Cornicen stores no mail credentials.
