# script-purpose: Resolve production adapter dependencies only after the release gate.
# script-class: pipeline-tool
# script-trigger: Engine adapter dispatch.
# script-tests: tests/test_task1_b2.py, tests/test_task2_b2.py
"""Read engine configuration lazily; return adapter closures without side effects.

Library API with no process exit codes; transport is constructed only on invocation.
"""
from pathlib import Path
from cornicen.fetch import Http
from cornicen.sources.github_advisories import GitHubAdvisories, GitHubState


def production_factories(engine, *, http_factory=None):
    def github():
        config = engine.config
        http = http_factory() if http_factory is not None else Http(
            config.user_agent, config.user_agent_overrides,
            data_dir=Path(config.db_path).parent, download_budgets=config.download_budgets)
        return GitHubAdvisories(http, engine.watches, GitHubState(engine.store), engine._now)
    def msrc():
        from cornicen.sources.msrc_csaf import MsrcCsaf, MsrcState
        config = engine.config
        http = http_factory() if http_factory is not None else Http(
            config.user_agent, config.user_agent_overrides,
            data_dir=Path(config.db_path).parent, download_budgets=config.download_budgets)
        return MsrcCsaf(http, MsrcState(engine.store), engine._now,
                        data_dir=Path(config.db_path).parent)
    return {'github': github, 'msrc': msrc}
