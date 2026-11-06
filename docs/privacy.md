# Privacy and network traffic

← [README](../README.md)

## What leaves the host

- **Matching is local.** Cornicen downloads whole public datasets (CVE List, KEV, EPSS bulk). It sends no product name, version or CVE ID to any data source in v1.
- **Notifications carry your data to the channel you configure.** An alert names the product and version it matched. If your ntfy server is someone else's, they see that. Self-host ntfy for end-to-end privacy.
- **No telemetry, analytics or update check.** This page lists every host contacted by default.
- **v1.1 caveat:** repository-specific checks (latest-release, GitHub advisories) and per-CVE lookups reveal what you watch to those hosts. Each will be opt-in and say so.
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
There are no other scheduled service calls.

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
Nothing about the watch list is sent either way: the requests are the same
public release listings and archives. Archive download hosts never receive the token.

The minute log line's `report` and `github` blocks contain only aggregate counts,
an auth status word and integers (or null when unavailable). They contain no watch
IDs, names, vendor/product strings, CVE IDs or diagnostic free text.
