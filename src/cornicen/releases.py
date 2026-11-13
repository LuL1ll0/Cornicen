"""Opt-in release checks; upstream text stays in private state and digest bodies."""

from copy import copy
from datetime import datetime, timedelta
from hashlib import sha256
import json

from cornicen.versions import compare
from cornicen.store import TransactionAborted


def release_behind(watch, tag):
    if not watch.latest_release:
        return False
    prefix = watch.release_tag_prefix
    version = tag.removeprefix(prefix) if prefix else tag
    return compare(version, watch.version, watch.scheme) == 1


def repositories_for(engine):
    return sorted({w.latest_release.lower() for w in engine.watches if w.latest_release})


class ReleaseChecker:
    def __init__(self, github):
        # Provider dispatch is explicit; new providers need their own transport policy.
        self.providers = {'github': github.latest_release}
        self.github = github
        self.applied = None

    def _github_deferred(self, store, now):
        active = self.github.http.github_token is not None
        deadline = store.get_meta('github_retry_at')
        mode = store.get_meta('github_retry_mode') or 'none'
        if (deadline and mode in ('any', 'token' if active else 'none')
                and now < datetime.fromisoformat(deadline)):
            return True
        rate = store.get_meta('github_rate_limit')
        if rate:
            rate = json.loads(rate)
            return rate['remaining'] <= 0 and now < datetime.fromisoformat(rate['reset'])
        return False

    def check(self, engine):
        """Fetch after delivery without a transaction, then atomically record results.

        All repositories and authentication retries share a ten-second transport
        budget. The shared HTTP client interrupts stalled socket transfers.
        """
        store, now = engine.store, engine._now()
        if engine.db.in_transaction:
            raise RuntimeError('Release checks require no transaction')
        repositories = repositories_for(engine)
        if not repositories:
            # Disabling all checks removes their operational health obligation.
            with store.transaction():
                engine.db.execute("DELETE FROM health WHERE source='releases'")
            return
        results = self._fetch(store, now, repositories)
        with store.transaction():
            self._record(engine, repositories, results)

    def _fetch(self, store, now, repositories):
        deadline_at = self.github.http.clock() + 10
        results = []
        for repository in repositories:
            key = 'release_check:' + repository
            saved = store.get_meta(key)
            state = json.loads(saved) if saved else None
            if state is None or not (now < datetime.fromisoformat(state['checked']) + timedelta(days=1)
                                     and now >= datetime.fromisoformat(state['checked'])):
                state = dict(checked=now.isoformat(), failed=False, release=None)
                provider, path = repository.split(':', 1)
                try:
                    if provider == 'github' and self._github_deferred(store, now):
                        raise ValueError('Deferred')
                    response = self.providers[provider](path, now, deadline_at=deadline_at)
                    if response.status != 404:
                        value = json.loads(response.body)
                        if (not isinstance(value, dict) or not isinstance(value.get('tag_name'), str)
                                or type(value.get('draft')) is not bool
                                or type(value.get('prerelease')) is not bool):
                            raise ValueError('Invalid release')
                        if not value['draft'] and not value['prerelease']:
                            state['release'] = value['tag_name']
                except TransactionAborted:
                    raise
                except Exception:
                    # Never persist response/exception text, including transport URLs.
                    state['failed'] = True
            results.append((repository, key, state))
        return results

    def signature(self, engine):
        return (engine._canonical_watches(engine.watches), tuple(
            (r, engine.store.get_meta('release_check:' + r))
            for r in repositories_for(engine)))

    def prepare(self, engine):
        """Snapshot on the scheduler thread; returned job has no database handle."""
        repositories = repositories_for(engine)
        now = engine._now()
        if not repositories:
            self.applied = None
            with engine.store.transaction():
                engine.db.execute("DELETE FROM health WHERE source='releases'")
            return None
        signature = self.signature(engine)
        due = False
        for repository in repositories:
            saved = engine.store.get_meta('release_check:' + repository)
            state = json.loads(saved) if saved else None
            if state is None or not (datetime.fromisoformat(state['checked']) <= now
                                     < datetime.fromisoformat(state['checked']) + timedelta(days=1)):
                due = True
        # Cached tags still need comparison after a watch version/prefix edit.
        if not due:
            if self.applied == signature:
                return None
            results = [(r, 'release_check:' + r,
                        json.loads(engine.store.get_meta('release_check:' + r))) for r in repositories]
            with engine.store.transaction():
                self._record(engine, repositories, results)
            self.applied = signature
            return None
        state = ReleaseState(engine.store, repositories)
        github = copy(self.github)
        github.http = copy(self.github.http)
        github.store = state
        github._cache_get = state._cache_get
        github._cache_put = state._cache_put
        github._cache_touch = state._cache_touch
        github._cache_delete = state._cache_delete
        return ReleaseJob(ReleaseChecker(github), state, repositories, now)

    def _record(self, engine, repositories, results):
        store = engine.store
        failed = compared = unknown = 0
        for repository, key, state in results:
            store.set_meta(key, json.dumps(state))
            failed += state['failed']
            tag = state['release']
            for watch in engine.watches:
                if not watch.latest_release or watch.latest_release.lower() != repository:
                    continue
                if tag is None:
                    unknown += 1
                    continue
                version = tag.removeprefix(watch.release_tag_prefix) if watch.release_tag_prefix else tag
                result = compare(version, watch.version, watch.scheme)
                if result is None:
                    unknown += 1
                    continue
                compared += 1
                if result == 1:
                    record_id = 'release:' + sha256((repository + '\0' + tag).encode()).hexdigest()
                    body = dict(record_id=record_id, watch_id=watch.id, name=watch.name,
                                product=watch.match[0][1] if watch.match else watch.product_only[0],
                                version=watch.version, repository=watch.latest_release,
                                release_behind=True, tag=tag)
                    engine._event(watch.id, record_id, 'release_behind', 1, body)
        engine._health('releases', 'unhealthy' if failed else 'healthy',
                       f'Release checks: {len(repositories)}; failed: {failed}; compared: {compared}; could not compare: {unknown}',
                       'failed' if failed else 'recovered')


class ReleaseState:
    """Plain Python metadata/cache snapshot, with optimistic scheduler-side merge."""

    def __init__(self, store, repositories):
        keys = ['github_auth', 'github_rate_limit', 'github_retry_at', 'github_retry_mode']
        keys += ['release_check:' + r for r in repositories]
        self.original = {key: store.get_meta(key) for key in keys}
        self.meta = dict(self.original)
        self.cache = {}
        for repository in repositories:
            url = 'https://api.github.com/repos/' + repository.split(':', 1)[1] + '/releases/latest'
            row = store.connection.execute('SELECT * FROM http_cache WHERE url=?', (url,)).fetchone()
            self.cache[url] = dict(row) if row else None
        self.original_cache = dict(self.cache)

    def get_meta(self, key):
        return self.meta.get(key)

    def set_meta(self, key, value):
        self.meta[key] = value

    def _cache_get(self, url):
        return self.cache.get(url)

    def _cache_put(self, url, etag, link, body, used_at):
        self.cache[url] = dict(url=url, etag=etag, link=link, body=body, used_at=used_at)

    def _cache_touch(self, url, used_at):
        self.cache[url] = dict(self.cache[url], used_at=used_at)

    def _cache_delete(self, url):
        self.cache[url] = None

    def merge(self, github):
        # CVE polling may have updated shared metadata while this job ran. Never
        # overwrite those newer values with a stale snapshot.
        retry_keys = ('github_retry_at', 'github_retry_mode')
        if all(github.store.get_meta(k) == self.original.get(k) for k in retry_keys):
            for key in retry_keys:
                if self.meta.get(key) != self.original.get(key):
                    github.store.set_meta(key, self.meta[key])
        for key, value in self.meta.items():
            if key in retry_keys:
                continue
            if value != self.original.get(key) and github.store.get_meta(key) == self.original.get(key):
                github.store.set_meta(key, value)
        for url, value in self.cache.items():
            row = github._cache_get(url)
            current = dict(row) if row else None
            if value == self.original_cache.get(url) or current != self.original_cache.get(url):
                continue
            if value is None:
                github._cache_delete(url)
            else:
                github._cache_put(**value)


class ReleaseJob:
    def __init__(self, checker, state, repositories, now):
        self.checker, self.state = checker, state
        self.repositories, self.now = repositories, now
        self.results = None

    def fetch(self):
        self.results = self.checker._fetch(self.state, self.now, self.repositories)

    def record(self, checker, engine):
        with engine.store.transaction():
            self.state.merge(checker.github)
            # Use current watches: reloads while fetching cannot resurrect a
            # disabled repository or an obsolete watch/version.
            active = repositories_for(engine)
            results = [r for r in self.results if r[0] in active]
            if active:
                checker._record(engine, [r[0] for r in results], results)
            else:
                engine.db.execute("DELETE FROM health WHERE source='releases'")
        if active == [r[0] for r in results]:
            checker.applied = checker.signature(engine)
        if self.checker.github.http.github_token is None:
            checker.github.http.github_token = None
