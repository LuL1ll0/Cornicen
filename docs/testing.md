# Testing a deployment

← [README](../README.md)

## Private acceptance list

Keep your real watch list and known historical CVEs outside the repository.
After ingesting the public datasets, create a private TOML acceptance file:

```toml
[[expect]]
watch_id = "proxy"
cve = "CVE-2099-0001"
```

Use one `[[expect]]` entry per known (watch, CVE) pair. The watch ID must be in
your current watch list. Mount the private file read-only into the container,
then run:

```sh
docker compose exec cornicen python -m cornicen replay --list /config/acceptance.toml
```

Replay evaluates stored records against the current watches and aliases without
fetching or delivering notifications. It prints `matched` or `not matched` for
each expected CVE and exits 1 if any expectation fails. Missing retained records
can cause failures; inspect them before trusting a deployment. Run it again after
watch changes. The public regression gate is `make gate`; its replay fixtures
check exact notification sequences without network access.

The gate includes seeded fuzz properties with 2,000 cases per property/scheme by
default. Run a longer local check with:

```sh
CORNICEN_FUZZ_CASES=100000 PYTHONPATH=src python3 -m unittest tests.test_fuzz
```

Failures print the base seed, property seed, and case index. Set
`CORNICEN_FUZZ_SEED` to replay a base seed; `.build/fuzz.out.md` records the
results and minimal failing inputs.

## Scheduled acceptance self-test

Keep a separate private watch file pinned to versions that those CVEs hit.
Use invented inventory such as `zyphora:relay` at version `4.2.3` when sharing
examples. Configure both paths in `cornicen.toml`:

```toml
acceptance_list_path = "/config/acceptance.toml"
acceptance_watchlist_path = "/config/pinned-watchlist.toml"
acceptance_interval_days = 7
```

Both paths are required together. Omit both to disable the self-test.
The interval must be a positive integer and defaults to 7 days.
After baseline completion, the daemon checks on its first tick, after more than
the interval since the persisted last run, and when either file stamp changes.
File stamps include modification time, size and inode. A restart forces one check
on the first tick after baseline completion, even if the files are unchanged and
the persisted last run is recent. Evaluation uses records available after that
tick's ingestion and the engine's aliases; it does not fetch historical CVEs.
While the acceptance component is unhealthy, checks retry every hour instead of
waiting for the configured interval.
Last-run time and health commit together after evaluation; failed transactions
retry next tick. Repeated unhealthy results emit one alert until recovery.

Each entry must resolve to AFFECTED. UNKNOWN is a regression, even with KEV.
An absent stored record is could-not-check, even with KEV. Empty lists, unknown
watch IDs and unreadable or invalid files are rejected. `[[accept]]` suppressions
are ignored. Pinned watches never enter the live inventory or create match alerts.
Failures raise an `acceptance` health alert and mark the container unhealthy,
like any other unhealthy component. Recovery raises a recovered alert.
Health details contain counts and fixed words only.

The list is parsed before pruning every tick. Valid lists replace in-memory
retention holds and repair stored holds best-effort. In-memory holds protect
records even if the write fails. Pruning also honors valid stored arrays of
strings; garbage metadata holds nothing. A broken list keeps the last holds.
Removing an ID from a valid list releases its hold; other retention rules still apply.

```sh
cornicen selftest
```

This command uses the configured paths and a read-only database. It prints each
watch/CVE result and a count summary. Exit 0 means all pass, 1 means regression,
3 means at least one record could not be checked, and 2 means command error,
including missing configuration. Exit 3 takes priority over 1. It writes no
health or metadata. `replay --list` keeps its existing matching rules.
