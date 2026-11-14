# Writing and tuning a watch list

← [README](../README.md)

## Watch entries and matching rules

Each `[[watch]]` needs a stable `id`, display `name`, vendor-scoped `match`
identities, `version`, and comparison `scheme`. Changing a name keeps its identity;
changing a version re-matches stored records. Use `semver`, numeric `dotted`,
`debian`, CPython `python`, or equality-only `opaque`. Comparator ranges such as
`">=1.0.0, <2.0.0"` are supported. Declare `eol = true` for unsupported versions.
`status`, `report`, and `watch check` then show the watch ID and
"coverage limited: the vendor issues no advisories for unsupported versions; absence of alerts is not evidence of safety".
Status JSON exposes these IDs in `eol_coverage_limited`; report JSONL sends the
human notice to stderr. `watch check --file` reports the candidate file's EOL watches. See the
[command reference](cli.md). This notice does not change health, exit codes, or notifications.

`product_only` is an explicit loose match across vendors and caps applicability at
unknown. Prefer scoped identities. Identity normalisation removes U+00AD, U+200B, U+200E, U+200F, U+202A–U+202E, U+2060, U+2066–U+2069 and U+FEFF before NFKC, casefolding and whitespace collapse. It preserves U+200C/U+200D, variation selectors, Hangul fillers and U+034F. Opaque versions use plain NFKC, casefolding and whitespace collapse without this removal set. Punctuation is kept. Placeholder products never match;
a placeholder vendor can match a real product only through `product_only`.
For CPython use `python`, which orders three numeric components and optional
`aN`, `bN` or `rcN` pre-releases. Other PEP 440 forms remain unknown.
Synology DSM build/update strings can use `debian`.
For point watches only, a numeric wildcard start with a non-wildcard upper bound textually in the same line (`5.4.*` below `5.4.12`) becomes that line's first release (`5.4.0`), while a version in the line below that release stays unknown;
other wildcards, `unspecified` bounds and prose remain unknown.
When a version is outside every affected range a CNA entry lists and all
comparisons are decidable, `defaultStatus: affected` yields **unknown**, with
evidence “outside every range the CNA listed; the CNA's default says affected”.
This rule applies equally before, between and after the listed ranges.
Explicit status rows and covering ranges take precedence. An entry with no
affected ranges retains its existing default behavior. Range watches evaluate
all allowed versions: any affected cell yields **affected**, and every cell must
be excluded to return **not affected**. Starts of `0`, `0.0`, `0.0.0` or `*` in
explicit ranges mean unbounded below and never enter version ranking or lookup.
Across matching entries, an affected result wins. An unknown result wins over
an exclusion inferred only from another entry's history.
History inference requires an omitted/unknown default, decidable rows and
transitions, no covering row, and affected history starting at zero or `*`
(or an upper-bounded comparator unbounded below). Explicit unaffected rows and
unaffected defaults retain their precedence. Undecidable comparisons stay unknown.
The versioned built-in alias map accounts for spelling variants; extend it with
a local `aliases_path` containing `version` and `[[alias]]` groups of `identities`.
Changes to effective alias groups, including local edits, re-check stored CVEs
at the next start, including during bootstrap. The first start after upgrading
also re-checks retained CVEs when no alias fingerprint is stored. Version-only
edits do nothing. Resulting alerts use the ordinary digest and urgent rules.

Validate before starting (no database is needed), then inspect the stored CVEs
after bootstrap before trusting your identities:

```sh
docker compose run --rm cornicen python -m cornicen watch check
```

```sh
docker compose exec cornicen python -m cornicen watch check --days 90
docker compose exec cornicen python -m cornicen report
```

`watch check` validates the whole file, reports collisions including aliases,
and prints matched and near-miss CVEs per watch. Matches are affected or unknown
with exploitation evidence. Near misses include excluded or unknown versions
and shared vendor or product names. The window uses the CVE publication time,
falling back to local ingestion time. It performs no fetches; an empty database
cannot establish coverage and reports "no records ingested yet". Use near misses
to discover a CNA's vendor and product spelling, then add that scoped identity
to `match` or a local alias group. For example, F5 publishes nginx as
`F5:NGINX Open Source`; the built-in aliases connect it to `nginx:nginx` and
`f5:nginx`, while keeping `F5:NGINX Plus` separate. The example inventory uses
real CNA identities for nginx, OpenWrt, nginx-ui and Jellyfin. Review near
misses after tuning to check coverage.
Collisions are reported without rejecting an otherwise valid list by default.

The running scheduler reloads on file modification. Startup also compares the
file with the last applied watch list stored in SQLite and re-matches changes
before sending any queued notifications. Removing and re-adding a watch with the
same `id` can repeat an already-delivered alert (a known, low-impact limitation). Likewise, if a
re-match started during bootstrap fails and only succeeds after bootstrap completes, that
snapshot match is sent as its own alert and is missing from the baseline summary. A rejected reload keeps the
previous list and marks `watchlist` unhealthy until a valid reload. Mounting a
directory read-only at `/config` instead of individual files can help editors
that replace files atomically make changes visible in an existing container.

`report` prints a one-line count summary, then JSON-lines items under these headings:

- **Baseline: affected** — affected pairs recorded during baseline.
- **Baseline: exploited (unknown version)** — baseline pairs with unknown applicability and known exploitation.
- **Open matches** — affected or exploited unknown-version pairs outside baseline.
- **Not affected (recorded, no alert)** — pairs recorded as not affected, including baseline pairs.
- **Dead letters** — records that exhausted retries.

Pair items include their alias map version. Groups do not overlap; unknown pairs
without known exploitation are omitted.
`status` reports source health, a sanitised last source error, and reconciliation. `healthcheck` exits 0 when
healthy and 1 otherwise, including when the database is unavailable.
Run locally on Python 3.11+ with `PYTHONPATH=src python3 -m cornicen --config
/path/to/cornicen.toml status`. Runtime dependencies are standard library only.

## Accept entries

An `[[accept]]` records an explicit decision to hold alerts for one watch/CVE
pair. It does not alter matching or ingest state. For example:

```toml
[[accept]]
cve = "CVE-2026-0001"
watch = "proxy"
reason = "Module not built"
until = 2027-03-01

[[accept]]
cve = "CVE-2026-0002"
watch = "proxy"
reason = "Local fix applied to this version"
until_version_change = true
version = "1.25.3"
```

CVE IDs are case-insensitive and stored uppercase. Watch IDs use
`[A-Za-z0-9._-]{1,64}`. Each entry requires a nonempty reason (at most 200
characters after trimming) and at least one lapse condition. `until` accepts a
TOML date or a quoted `YYYY-MM-DD`; it includes that entire date in the configured
`timezone`. `until_version_change = true` requires `version`, which must exactly
match the watch's version string to stay active. `version` is invalid without
that condition. With both conditions, whichever lapses first releases the pair.
Unknown keys, malformed entries and duplicate CVE/watch pairs reject the whole
file; duplicate watch IDs in pairs are compared without case.

Only ordinary new-match or acceptance-lapsed rows are held. They remain pending
in the outbox, with `accepted.held = true`, normal urgency and a due time rolled
forward to the next digest on refresh. High EPSS does not break through: it is a
probability, not evidence of exploitation. KEV or known exploitation always
breaks through and the alert includes `Accepted: <reason> (until <date or version
change>) — alerting anyway: KEV listed` (or `exploited`). Corrections, health
messages and the baseline summary are never held. A held pair that clears sends
no correction because it was never notified.

Date expiry, a version change or removing an entry releases a held row for the
next digest under ordinary urgency rules. Its alert includes `Acceptance lapsed
(<why>): <reason>`. A lapsed entry also creates a notice for an active pair that
was previously notified or classified as baseline. There is **one lapse notice
per episode**. A pair that broke through on KEV still gets its one lapse notice
when the entry later lapses. Extending an entry and lapsing it again in that same
episode does not produce another notice. Reasons in notifications have control characters
replaced with spaces, collapsed whitespace and a 160-character cap.
Removing a watch drops its pending rows, held ones included, as it always has.
Re-adding the watch re-matches it, and an entry that is still active holds the
new row again.

The scheduler reloads accept edits without a restart or re-match. A rejected
reload retains both the previous watches and accept entries. New entries affect
pending rows on their next refresh, at the latest when due. `watch check` lists
entry states and warns about unknown watches, lapsed entries, dates more than
`accept_warn_days` away (default 180), and entries matching no stored affected
or unknown-and-exploited record. Without a database, matching is marked **not
checked**. Unknown watches are ignored by the engine. Warnings do not reject the
file; `--strict` exits 1 for them. Version-change-only entries never warn as long.

Deploy **0.1.6 before copying a watch list with accept entries**: v0.1.5 rejects
`[[accept]]` as an unknown table.

Command failures use watch or accept entry indexes without inventory text.
`watch check` validation lines retain valid IDs to locate the entry, but omit
unknown keys, paths and invalid version constraint text. TOML failures report
the file role and line/column when available. See
[private command failures](privacy.md#command-failure-diagnostics).

## Latest-release checks (opt-in per watch)

Add these optional fields to a watch to receive a normal digest item saying
“you are behind” when its upstream has a newer release:

```toml
latest_release = "github:example-org/widget"
release_tag_prefix = "v"   # optional; stripped before comparison
```

There is no default list. Without `latest_release`, nothing is checked.
The provider prefix is required; only `github:` is supported. Owner and repository
must use GitHub's character set; URLs, extra paths and other providers reject
the watch list without echoing the value. A prefix requires `latest_release`
and must be nonempty printable ASCII without spaces, at most 100 characters.

This is a privacy choice: each enabled check tells GitHub which repository you
run. The request carries the repository path only, never the watched version.
With the optional GitHub token it is tied to your account as well as your IP.
See [privacy](privacy.md). Status shows only how many watches have checks enabled.

Each repository is fetched at most once per day, shared across watches and
restarts, using the existing GitHub token, ETags and rate budget. The watch's
own scheme compares the tag after removing the optional prefix. Unparseable
tags, draft releases, prereleases and repositories without releases mean “could
not compare”; they never mean “behind”. Range watches whose version cannot be
compared also remain unknown. Fetch failures mark only `releases` unhealthy.

One `release_behind` event is recorded per watch and latest tag. A newer tag
can send another item. Updating the watched version to the latest clears any
pending item silently. These items appear in that watch's digest block at normal
priority, never urgent. Tags are upstream text and stay out of stdout, heartbeat,
status and health detail.

Release checks run on one background worker after the cycle flush. The scheduler
records completed results on a later tick, in its own transaction. After ten
seconds an unfinished check makes `releases` unhealthy; CVE ingestion and delivery
continue. A running check is never duplicated, even if DNS never returns. A
restart retries any check whose results were not committed.
