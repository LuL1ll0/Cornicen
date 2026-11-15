# script-purpose: Enumerate stable GitHub repository advisories within durable local budgets.
# script-class: pipeline-tool
# script-trigger: Effective GitHub adapter dispatch.
# script-tests: tests/test_task1_b2.py
"""Read consented watches and HTTP responses; write accounting through GitHubState.

Library API; no process exit codes. Logical outcomes are committed by AdapterStore.
"""
import json
from http.client import HTTPException
from urllib.error import URLError
import re
from datetime import timedelta
from urllib.parse import quote, urlsplit, parse_qsl, unquote

from cornicen.adapterstore import AdapterStore, bounded_wait, canonical, digest, instant, stamp
from cornicen.fetch import _destination
from cornicen.feedvalidate import decode_json, validate_advisory

# ponytail: Local ceilings only; GitHub's per-IP allowance is shared with other
# clients. These do not guarantee capacity. Raise only with an authenticated budget.
CYCLE_LIMIT, HOUR_LIMIT, WINDOW, PAGE_CAP = 30, 60, 3600, 12


def resource_key(repository):
    return 'github/' + repository.casefold() + '/advisories'


def normalise(raw, repository, *, observed_at, detail=False):
    """Map publisher fields without suppressing individually invalid members."""
    identity = raw.get('ghsa_id')
    if not isinstance(identity, str) or not re.fullmatch(r'GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}', identity):
        return dict(id=None, mapping_error='invalid GHSA', ghsa_digest=digest(raw))
    cve = raw.get('cve_id')
    result = dict(id=identity, title=raw.get('summary'), url=raw.get('html_url'),
                  published=raw.get('published_at'), updated=raw.get('updated_at'),
                  withdrawn=raw.get('withdrawn_at'), products=[], evidence=[],
                  cves=[cve] if isinstance(cve, str) and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', cve) else [],
                  identifiers=raw.get('identifiers', []))
    try:
        if raw.get('state') != 'published':
            if not detail or not isinstance(raw.get('state'), str):
                raise ValueError()
            result['retraction'] = 'administrative'
        vulnerabilities = raw['vulnerabilities']
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            raise ValueError()
        for n, vulnerability in enumerate(vulnerabilities):
            package = vulnerability['package']
            name, ecosystem = package['name'], package['ecosystem']
            if not isinstance(name, str) or not name or not isinstance(ecosystem, str) or not ecosystem:
                raise ValueError()
            product = f'pkg-{n}'
            result['products'].append(dict(id=product, name=f'github-selector:{repository}#{ecosystem}#{name}'))
            text = vulnerability.get('vulnerable_version_range')
            if text is not None and not isinstance(text, str):
                raise ValueError()
            evidence = dict(product_id=product, scheme='opaque', status='under_investigation')
            if text:
                evidence.update(status='known_affected', range={'github': text})
            fix = vulnerability.get('patched_versions')
            if isinstance(fix, str) and re.fullmatch(r'[^\s,|]+', fix):
                evidence['fix'] = fix
            result['evidence'].append(evidence)
        validate_advisory(result, source='github', observed_at=observed_at)
    except (KeyError, TypeError, ValueError):
        return dict(id=identity, mapping_error='invalid advisory')
    return result


class GitHubState:
    """The adapter's sole durable state boundary; each write is a transaction."""
    def __init__(self, store):
        self.store = store
        self.adapter_store = AdapterStore(store, '.')

    def meta(self, key, default=None):
        value = self.store.get_meta('github:' + key)
        return json.loads(value) if value is not None else default

    def adapter_retries(self):
        return [dict(r) for r in self.store.connection.execute("SELECT * FROM adapter_retries WHERE source='github'")]

    def manifests(self):
        return [dict(r) for r in self.store.connection.execute("SELECT * FROM manifests WHERE source='github'")]

    def known_members(self, resource):
        return self.adapter_store.known_members('github', resource)

    def _put(self, key, value):
        self.store.set_meta('github:' + key, canonical(value))

    def charge(self, tick, *, repository, first=False):
        with self.store.transaction():
            requests = [r for r in self.meta('requests', []) if (instant(tick)-instant(r)).total_seconds() < WINDOW]
            requests.append(tick)
            self._put('requests', requests)
            if first:
                schedule = self.meta('schedule', {})
                schedule[repository] = dict(schedule.get(repository, dict(expected_pages=1)), last_attempt=tick)
                self._put('schedule', schedule)

    def set_pages(self, repository, expected_pages):
        with self.store.transaction():
            schedule = self.meta('schedule', {})
            schedule[repository] = dict(schedule.get(repository, {}), expected_pages=expected_pages)
            self._put('schedule', schedule)

    def set_hold(self, until):
        with self.store.transaction():
            self._put('rate_hold_until', until)

    def set_repo_id(self, repository, id, tick):
        with self.store.transaction():
            ids = self.meta('repo_ids', {})
            ids[repository] = dict(id=id, tick=tick)
            self._put('repo_ids', ids)

    def check_detail(self, repository, identity, tick):
        with self.store.transaction():
            checks = self.meta('detail_checks', {})
            checks.setdefault(repository, {})[identity] = tick
            self._put('detail_checks', checks)


class Interrupted(ValueError):
    pass


class ResponseFailure(Exception):
    def __init__(self, response):
        self.response = response


class GitHubAdvisories:
    def __init__(self, http, watches, state, clock):
        self.http, self.state, self.clock = http, state, clock
        self.repositories = sorted({s.repository for w in watches for s in w.github})

    def required_resources(self):
        return tuple(resource_key(r) for r in self.repositories)

    def retry(self, resource):
        return ()

    def audit(self, resource):
        return ()

    def _remaining(self):
        count = sum((self.now-instant(r)).total_seconds() < WINDOW for r in self.state.meta('requests', []))
        return min(CYCLE_LIMIT-self.spent, HOUR_LIMIT-count)

    def _get(self, url, repository, operation='listing'):
        base = '/repos/' + repository
        def validate(hop):
            _destination(hop, 'github_advisories')
            path = unquote(urlsplit(hop).path)
            if operation == 'listing':
                self._listing_path(path, repository)
            elif path.casefold() != (base + ('' if operation == 'metadata' else '/security-advisories/' + operation)).casefold():
                raise Interrupted('foreign endpoint')
            if self._remaining() <= 0:
                raise Interrupted('rate budget')
            self.state.charge(self.tick, repository=repository, first=repository not in self.started)
            self.started.add(repository)
            self.spent += 1
        response = self.http.get(url, source='github_advisories', validate_hop=validate)
        if response.status in (403, 429):
            wait = bounded_wait(response.headers, self.now)
            if wait is not None:
                self.state.set_hold(stamp(self.now + timedelta(seconds=wait)))
        return response

    def _listing_path(self, path, repository):
        if path.casefold() == ('/repos/' + repository + '/security-advisories').casefold():
            return
        match = re.fullmatch(r'/repositories/([0-9]+)/security-advisories', path)
        if not match:
            raise Interrupted('foreign endpoint')
        wanted = int(match[1])
        cached = self.state.meta('repo_ids', {}).get(repository)
        if cached is None or cached['id'] != wanted:
            if repository not in self.looked_up:
                self.looked_up.add(repository)
                response = self._get('https://api.github.com/repos/' + repository, repository, 'metadata')
                if response.status != 200:
                    raise ResponseFailure(response)
                try:
                    data = decode_json(response.body)
                    if type(data['id']) is not int or data['id'] <= 0 or data['full_name'].casefold() != repository:
                        raise ValueError()
                except (ValueError, TypeError, KeyError, AttributeError):
                    raise Interrupted('foreign endpoint') from None
                self.state.set_repo_id(repository, data['id'], self.tick)
                cached = data
            if cached is None or cached['id'] != wanted:
                raise Interrupted('foreign endpoint')

    def _traverse(self, repository):
        url = 'https://api.github.com/repos/' + '/'.join(quote(p, safe='') for p in repository.split('/')) + '/security-advisories?state=published&sort=created&direction=desc&per_page=100'
        seen, members, topology = set(), [], []
        while True:
            parsed = urlsplit(url)
            key = (repository, unquote(parsed.path).casefold(), tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True))))
            if key in seen:
                raise Interrupted('loop')
            seen.add(key)
            response = self._get(url, repository)
            if response.status != 200:
                raise ResponseFailure(response)
            try:
                page = decode_json(response.body)
                if not isinstance(page, list) or any(not isinstance(m, dict) for m in page):
                    raise ValueError()
            except (ValueError, TypeError):
                raise ResponseFailure(response) from None
            mapped = [normalise(m, repository, observed_at=self.tick) for m in page]
            members.extend(mapped)
            topology.append([m['id'] for m in mapped])
            self.pages_seen = max(self.pages_seen, len(topology))
            links = []
            for link in re.finditer(r'<([^>]+)>([^<]*)', response.headers.get('link', '')):
                relation = re.search(r'(?:^|;)\s*rel\s*=\s*(?:"([^"]*)"|([^;,\s]+))', link[2], re.I)
                if relation and 'next' in (relation[1] or relation[2]).split():
                    links.append(link[1])
            if not links:
                return members, topology
            if len(topology) >= PAGE_CAP:
                raise Interrupted('page cap')
            if len(links) != 1:
                raise Interrupted('foreign endpoint')
            url = links[0]

    def _repository(self, repository, expected):
        path = resource_key(repository)
        self.pages_seen = 0
        try:
            previous = None
            for traversal in range(3):
                if traversal == 2 and self._remaining() < self.pages_seen:
                    raise Interrupted('unstable')
                members, topology = self._traverse(repository)
                signature = digest([members, topology])
                if signature == previous:
                    break
                previous = signature
            else:
                raise Interrupted('unstable')
            self.state.set_pages(repository, len(topology))
            missing = self.state.known_members(path) - {m['id'] for m in members}
            unresolved = set(missing)
            checked = self.state.meta('detail_checks', {}).get(repository, {})
            for identity in sorted(missing, key=lambda i: (checked.get(i, ''), i))[:5]:
                if self._remaining() <= 0:
                    break
                try:
                    response = self._get('https://api.github.com/repos/' + repository + '/security-advisories/' + quote(identity, safe=''), repository, identity)
                except Interrupted:
                    break
                self.state.check_detail(repository, identity, self.tick)
                if response.status in (403, 429):
                    raise ResponseFailure(response)
                if response.status == 404:
                    continue
                if response.status != 200:
                    raise ResponseFailure(response)
                try:
                    raw = decode_json(response.body)
                    member = normalise(raw, repository, observed_at=self.tick, detail=True)
                    validate_advisory(member, source='github', observed_at=self.tick)
                    if member['id'] == identity and (member.get('withdrawn') or member.get('retraction')):
                        members.append(member)
                        unresolved.remove(identity)
                except (ValueError, TypeError, AttributeError):
                    continue
            scoped = []
            for member in members:
                identity = member['id']
                owner = self.owners.get(identity)
                if owner is not None and owner != path:
                    member = dict(id=identity, mapping_error='repository conflict')
                elif identity and 'mapping_error' not in member:
                    self.owners[identity] = path
                scoped.append(member)
            members = scoped
            body = dict(advisories=members)
            if unresolved:
                body['coverage_complete'] = False
            return dict(path=path, status=200, body=canonical(body))
        except ResponseFailure as error:
            response = error.response
            # An unsolicited 304 must never reuse the store's logical cache.
            return dict(path=path, status=response.status, unconditional=True,
                        headers=response.headers, body=response.body or b'',
                        invalid_envelope=True,
                        invalid_status=200 < response.status < 300,
                        rate_limited=response.status in (403, 429))
        except (URLError, OSError, EOFError, HTTPException):
            return dict(path=path, status=0, transport_error=True)
        except ValueError as error:
            self.state.set_pages(repository, max(expected, self.pages_seen))
            reason = (str(error) if isinstance(error, Interrupted) else
                      {'HTTP response body size limit exceeded': 'body budget',
                       'Too many redirects': 'redirect limit'}.get(str(error), 'foreign endpoint'))
            return dict(path=path, unenumerated=True, reason=reason)

    def poll(self, *, cutoff=None):
        self.now = self.clock()
        self.tick = stamp(self.now)
        self.spent = sum(r == self.tick for r in self.state.meta('requests', []))
        self.started, self.looked_up = set(), set()
        hold = self.state.meta('rate_hold_until')
        if hold and self.now < instant(hold):
            return []
        self.owners = {}
        for manifest in self.state.manifests():
            for identity in self.state.known_members(manifest['resource']):
                self.owners.setdefault(identity, manifest['resource'])
        schedule = self.state.meta('schedule', {})
        retries = {r['resource']: r for r in self.state.adapter_retries()}
        manifests = {r['resource']: r for r in self.state.manifests()}
        def order(repository):
            path = resource_key(repository)
            if path in retries:
                return (0, retries[path]['next_attempt_at'], repository)
            manifest = manifests.get(path)
            if manifest and (self.now-instant(manifest['audited_at'] or manifest['fetched_at'])).total_seconds() >= 7*86400:
                return (1, manifest['audited_at'] or manifest['fetched_at'], repository)
            return (2, schedule.get(repository, {}).get('last_attempt', ''), repository)
        results = []
        for repository in sorted(self.repositories, key=order):
            manifest = manifests.get(resource_key(repository))
            # Resume may already have accepted this cycle's staged enumeration.
            if manifest and manifest['digest'] and manifest['fetched_at'] == self.tick:
                continue
            retry = retries.get(resource_key(repository))
            if retry and instant(retry['next_attempt_at']) > self.now:
                continue
            expected = schedule.get(repository, {}).get('expected_pages', 1)
            if self._remaining() < 2*min(expected, PAGE_CAP)+1:
                continue
            results.append(self._repository(repository, expected))
            if results[-1].get('rate_limited'):
                break
            hold = self.state.meta('rate_hold_until')
            if hold and self.now < instant(hold):
                break
        return results
