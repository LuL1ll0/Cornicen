# Cornicen

Self-hosted CVE alerter for homelabs: matches CVE List, KEV and EPSS locally and alerts via ntfy.

Cornicen is for homelabs and small networks. You tell it what you run. It watches the public vulnerability feeds, matches them on your own machine, and sends a push notification when something you run is affected. When nothing is, it stays quiet. When it can't see the feeds, it says so.

- **One container**, Python standard library only, SQLite on a volume. No account or API key for any data source.
- **Matching never leaves your host.** It downloads whole public datasets and sends no product name, version or CVE ID to any data source.
- **Alerts go to [ntfy](https://ntfy.sh)**, ideally one you host yourself.
- **Silent first run.** The first bootstrap records what already matches and sends one summary; after that you hear only about changes.

**Status:** version 0.1.6, pre-1.0 and maintained. Changes land on `main`; the version is in `pyproject.toml`.

## Contents

- [What an alert looks like](#what-an-alert-looks-like)
- [Where the data comes from](#where-the-data-comes-from)
- [Quick start](#quick-start)
- [Watch lists](#watch-lists)
- [Commands](#commands)
- [Design goals](#design-goals)
- [Limits](#limits)
- [Privacy](#privacy)
- [Getting help](#getting-help)
- [Development](#development)
- [License and prior art](#license-and-prior-art)

## What an alert looks like

An urgent alert, as Cornicen renders it (fictional CVE and inventory):

```text
🚨 Cornicen: CVE-2026-4321 — Example reverse proxy (nginx:nginx 1.25.3)
Why: new match · KEV added
KEV: listed 2026-10-30, CISA due 2026-11-20
EPSS 42% (98th pct, 2026-11-02)
Match: 1.25.3 is inside the CNA range >=1.25.0, <1.25.5 — affected
https://www.cve.org/CVERecord?id=CVE-2026-4321
CVE title: Example request smuggling in the HTTP/2 module
CNA CVSS score: 8.1
```

Anything listed in CISA's Known Exploited Vulnerabilities catalog (KEV), or affected with an EPSS score at or above the threshold (10% by default), goes out at once. Everything else waits for one daily digest, most severe first. Unknowns are shown as unknown: "KEV: not listed" means not listed, not "not exploited".

## Where the data comes from

| Source | What it gives | Polled |
|---|---|---|
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Every CVE record, with the affected products and versions each CNA published | hourly |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs known to be exploited in the wild | every 6 hours |
| [EPSS](https://www.first.org/epss/) | Daily probability that a CVE will be exploited in the next 30 days | daily |

## Quick start

Requires Docker Compose.

```sh
mkdir -p config secrets && chmod 700 config secrets
cp compose.example.yml compose.yml
cp examples/cornicen.example.toml config/cornicen.toml
cp examples/watchlist.example.toml config/watchlist.toml
```

1. In `config/cornicen.toml`, set your ntfy server and topic, your GitHub owner (`owner`, used in the User-Agent), digest time and time zone.
2. Put your ntfy token in `secrets/ntfy_token`, owned by UID 10001 with mode 0600. (No auth on your server? Remove the `environment` and `secrets` entries from `compose.yml`.)
3. Replace the example watch list with what you run (next section).

```sh
docker compose run --rm cornicen python -m cornicen watch check   # validate the watch list
docker compose up --build -d
docker compose exec cornicen python -m cornicen notify test       # check delivery
docker compose exec cornicen python -m cornicen status
```

The first bootstrap downloads the full CVE List (a few minutes) and sends one baseline summary. Run `cornicen report` to see what matched. Full install notes, including token-file rules, the hardened container settings, the pinned base image and a file-only dry-run mode, are in [docs/install.md](docs/install.md).

## Watch lists

One `[[watch]]` per product you run:

```toml
[[watch]]
id = "proxy"                 # stable ID; alerts and the CLI use it
name = "Example reverse proxy"
match = ["nginx:nginx"]      # vendor:product, as the CNA writes it
version = "1.25.3"           # or a range: ">=1.25.0, <1.26.0"
scheme = "semver"            # semver, dotted, debian, python or opaque
eol = true                   # optional: the vendor no longer supports this version
```

CNAs spell vendors and products inconsistently, so check what actually matches. After the first bootstrap, `watch check --days 90` shows matches and near misses for each watch, so you can find the spelling a CNA uses. Cornicen re-reads the file when it changes, and re-checks edited watches against the CVEs it has stored. Alias changes are re-checked at the next start.

Mark a version the vendor no longer supports with `eol = true`. Its alerts then lead with "unsupported by the vendor — fixes unlikely; isolate or replace", and `status`, `report` and `watch check` flag it as coverage limited: vendors stop publishing advisories for unsupported versions, so a quiet EOL watch is not a safe one.

Matching rules, aliases, version schemes and how unknowns are decided: [docs/watch-lists.md](docs/watch-lists.md).

## Commands

All of these run inside the container (`docker compose exec cornicen python -m cornicen …`) or locally on Python 3.11+.

| Command | What it does |
|---|---|
| `status` / `status --json` | Source health, last error, coverage; JSON for monitoring |
| `healthcheck` | Exit 0 if healthy, 1 if not (used by the container health check) |
| `report` | Everything that matched, grouped; filter with `--watch`, `--group`, `--format jsonl` |
| `explain CVE --watch ID` | Why one CVE did or didn't match one watch |
| `watch check` | Validate the watch list and show matches and near misses; `--file`, `--strict` |
| `outbox list` | Notifications waiting to be sent; `--failed` for retries |
| `notify test` | Send a test notification |
| `db backup --output PATH` | Consistent private copy of the database |
| `version compare A B --scheme S` | How two versions compare under a scheme |
| `replay --list FILE` | Check a deployment against CVEs you know should match |

Details and exit codes: [docs/cli.md](docs/cli.md). `replay` is covered in [docs/testing.md](docs/testing.md).

## Design goals

1. **Catch what hits your gear.** Each new match, KEV addition or correction on a watched item should produce exactly one notification within one poll cycle of being ingested.
2. **Deliver durably.** A crash-safe outbox retries until the notification is accepted. A lost acknowledgement can cause a duplicate, never a loss.
3. **Stay quiet otherwise.** No alerts for products you don't run, versions a record excludes, or edits that change nothing.
4. **Report blindness.** A source that can't be fetched, returns incomplete data or stops advancing is unhealthy, never "no new CVEs".
5. **Show what is known and unknown.** Alerts state their evidence.
6. **Be usable by strangers.** No accounts or keys, a fictional example inventory, one documented install.

The full ingestion, matching and delivery design is in [docs/spec.md](docs/spec.md).

## Limits

Cornicen only knows what the CVE List, KEV and EPSS publish, and CNA data is inconsistent. It can miss vulnerabilities or over-report them, so treat it as an early warning, not an audit. It never probes your systems or scans images; it knows only what you declare.

- **Not covered:** anything without a CVE record (a blog post, a GitHub issue), Apple (no official machine-readable feed), and Raspberry Pi-specific packages or firmware.
- **GitHub rate limit:** the CVE List is fetched from GitHub without a token, and GitHub allows 60 such requests an hour per IP address. Anything else on your network calling GitHub without a token draws on the same allowance. If it runs out, the CVE List source reports unhealthy until the hour resets.
- **Plex:** no machine-readable advisory feed was found, so coverage comes from CVE records alone. A latest-version check is planned.
- **Planned:** vendor advisory feeds, Debian data, NVD enrichment, release checks, more delivery channels.

## Privacy

Matching is local: Cornicen downloads whole public datasets and sends no product name, version or CVE ID to them. There is no telemetry, analytics or update check. Alerts do name the product and version they matched, so whoever runs your ntfy server sees them; self-host ntfy if that matters. The exact hosts contacted and the network safeguards are in [docs/privacy.md](docs/privacy.md).

## Getting help

Ask questions and report bugs in [GitHub Issues](https://github.com/LuL1ll0/cornicen/issues). Don't paste your real watch list into a public issue; a fictional one that reproduces the problem is enough. Report security vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Development

```sh
make gate
```

The gate runs the full unit, replay and fuzz suite with no network access. Testing a real deployment against CVEs you know should match: [docs/testing.md](docs/testing.md). How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md).

## License and prior art

MIT (SPDX: `MIT`); see [LICENSE](LICENSE). Maintained by [@LuL1ll0](https://github.com/LuL1ll0).

The silent first-run baseline, vendor-scoped version-bounded watches, a crash-safe outbox, and alerting on *what changed* rather than every record update are ideas seen in other open-source CVE watchers. Cornicen's code is written from this spec.
