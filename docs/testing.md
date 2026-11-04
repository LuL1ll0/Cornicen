# Testing a deployment

← [README](../README.md)

## Private acceptance list

Keep your real watch list and known historical CVEs outside the repository.
After ingesting the public datasets, create a private TOML acceptance file:

```toml
[[expect]]
watch_id = "proxy"
cve = "CVE-2026-1234"
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
