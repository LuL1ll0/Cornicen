# Writing and tuning a watch list

← [README](../README.md)

## Watch entries and matching rules

Each `[[watch]]` needs a stable `id`, display `name`, vendor-scoped `match`
identities, `version`, and comparison `scheme`. Changing a name keeps its identity;
changing a version re-matches stored records. Use `semver`, numeric `dotted`,
`debian`, CPython `python`, or equality-only `opaque`. Comparator ranges such as
`">=1.0.0, <2.0.0"` are supported. Declare `eol = true` for unsupported versions.

`product_only` is an explicit loose match across vendors and caps applicability at
unknown. Prefer scoped identities. Normalisation trims and collapses whitespace
and ignores case while keeping punctuation. Placeholder products never match;
a placeholder vendor can match a real product only through `product_only`.
For CPython use `python`, which orders three numeric components and optional
`aN`, `bN` or `rcN` pre-releases. Other PEP 440 forms remain unknown.
Synology DSM build/update strings can use `debian`;
wildcards, `unspecified` bounds and prose remain unknown.
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
before sending any queued notifications. A rejected reload keeps the
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
