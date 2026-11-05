# Contributing to Cornicen

Bug reports, fixes and documentation improvements are welcome.

## Before you start

- **Questions and bugs:** open a [GitHub Issue](https://github.com/LuL1ll0/cornicen/issues). Use a fictional watch list; never post your real inventory.
- **Security vulnerabilities:** report them privately, as described in [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue describing the change before writing code, so we can agree on the approach first. Not sure what to work on? Ask in an issue. The design is in [docs/spec.md](docs/spec.md).

## Making a change

1. Fork the repository and create a branch.
2. Keep to the project's constraints: Python 3.11+ standard library only, no new runtime dependencies, and no data sent anywhere beyond the hosts listed in [docs/privacy.md](docs/privacy.md).
3. Add or update tests for what you change. Tests run with no network access.
4. Run the gate and make sure it passes:

   ```sh
   make gate
   ```

5. Update the README or the page under `docs/` that describes the behaviour you changed.
6. Open a pull request that says what changed and why.

By contributing, you agree that your contribution is licensed under the project's MIT license.
