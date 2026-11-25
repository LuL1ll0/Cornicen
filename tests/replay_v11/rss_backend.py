"""Read action-indexed RSS scripts and write temporary replay state via real dispatch.

No network is used. The parent unittest runner exits 0 on success or 1 on failure.
"""

from dataclasses import replace
from io import BytesIO
import json
import re
from xml.etree import ElementTree as ET

from cornicen.adapterstore import canonical, instant
from cornicen.adapters import REGISTRY
from cornicen.fetch import Http
from cornicen.sources.synology_rss import SynologyRss, SynologyState
from tests.replay_v11.fixture_adapter import ValidationBackend
from tests.source_helpers import public_resolver


HOST = 'www.synology.com'
URL = 'https://www.synology.com/api/rssfeed/security/en-us'
HEADERS = {'User-agent': 'Cornicen/test'}
BROKEN = {'html': b'<html><body>Unavailable</body></html>',
          'empty': b'', 'malformed': b'<rss><channel></rss>'}
BUILD = 'Fri, 30 Oct 2026 09:00:00 +0800'
STATE_FIELDS = {'retention_summary', 'advisory_rows', 'evidence_rows', 'event_keys',
                'quarantine_rows', 'retry_detail', 'requests', 'request_trace', 'manifest_rows'}


def is_synology(name):
    return name.startswith('synology_')


def rss_body(items, last_build=BUILD):
    root = ET.Element('rss', version='2.0')
    channel = ET.SubElement(root, 'channel')
    ET.SubElement(channel, 'lastBuildDate').text = last_build
    for fields in items:
        item = ET.SubElement(channel, 'item')
        for key, value in fields.items():
            ET.SubElement(item, key).text = value
    return ET.tostring(root, encoding='utf-8')


def validate_script(script):
    if (not isinstance(script, dict) or set(script) - {'items', 'broken', 'last_build'}
            or ('items' in script) == ('broken' in script)):
        raise ValueError('RSS script requires items or a broken body')
    if 'broken' in script:
        if set(script) != {'broken'} or script['broken'] not in BROKEN:
            raise ValueError('unknown broken RSS body')
        return
    if not isinstance(script.get('last_build', BUILD), str) or not isinstance(script['items'], list):
        raise ValueError('invalid RSS channel or item list')
    for item in script['items']:
        if not isinstance(item, dict) or set(item) - {'title', 'link', 'description', 'pubDate', 'guid'}:
            raise ValueError('invalid RSS item fields')
        for key, value in item.items():
            if not isinstance(value, str):
                raise ValueError('RSS item fields must be text')
            if key in ('guid', 'link') and not re.fullmatch(
                    r'https://www\.synology\.com/[a-z]{2}-[a-z]{2}/(?:support/)?security/Synology_SA_99_\d{2}', value):
                raise ValueError('non-invented Synology item ID')


class ScriptedRss:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.scripts, self.requests = {}, []
        self.reset(0)

    def reset(self, action):
        self.action, self.used = action, False

    def add(self, action, script):
        validate_script(script)
        key = action, 'feed'
        assert key not in self.scripts, key
        self.scripts[key] = script

    def http(self):
        def resolve(host, port, **kwargs):
            assert host == HOST, host
            return public_resolver(host, port, **kwargs)
        return Http('Cornicen/test', {}, opener=self, resolver=resolve, data_dir=self.data_dir)

    def open(self, request, timeout):
        key = self.action, 'feed'
        trace = dict(method=request.get_method(), url=request.full_url, headers=dict(request.header_items()))
        assert trace == dict(method='GET', url=URL, headers=HEADERS), trace
        assert key in self.scripts and not self.used, ('unexpected RSS request', key)
        self.used = True
        self.requests.append(trace | dict(action=self.action, operation='feed'))
        script = self.scripts[key]
        body = (BROKEN[script['broken']] if 'broken' in script else
                rss_body(script['items'], script.get('last_build', BUILD)))
        response = BytesIO(body)
        response.status, response.headers = 200, {'content-type': 'text/xml'}
        return response


class SynologyBackend(ValidationBackend):
    def __init__(self, registry):
        super().__init__({'synology': replace(REGISTRY['synology'], gate='met')})
        self.server = ScriptedRss(self.tmp.name)
        self.action_index = 0
        self.script_action = None

    def start_engine(self):
        if self.engine is not None and self.engine.store is not self.store:
            self.engine.store._finalizer.detach()
        super().start_engine()
        self.engine.config.adapters['synology'] = True

    def dispatch(self):
        def factory():
            return SynologyRss(self.server.http(), SynologyState(self.store), self.engine._now,
                               retention_hours=48, interval_hours=24)
        self.server.reset(self.script_action)
        return self.engine.dispatch_adapters(registry=self.registry, factories={'synology': factory})

    def action(self, row):
        self.clock.now = instant(row['t'])
        if 'rss' in row:
            self.script_action = self.action_index
            self.server.add(self.script_action, row['rss'])
        elif 'cycle' in row:
            self.engine._health_verdicts = {}
            for ingest in self.ingests:
                with self.store.transaction():
                    self.engine._ingest(ingest)
            self.observed = {'classification': self.dispatch()}
            self.engine._flush()
            self.ingests.clear()
            self.script_action = None
        elif 'command' in row:
            super().action(row)
            self.observed = {'classification': {}}
        else:
            super().action(row)
        self.action_index += 1

    def snapshot(self):
        result = super().snapshot()
        db = self.store.connection
        result['retention_summary'] = SynologyState(self.store).retention()
        result['advisory_rows'] = {
            row['source_id']: dict(digest=row['digest'], revision=row['revision'],
                                   published=row['published'], updated=row['updated'], state=row['state'],
                                   cves=[cve['value'] for cve in json.loads(row['json'])['cves']],
                                   record=row['json'])
            for row in db.execute("SELECT * FROM advisories WHERE source='synology' ORDER BY source_id")}
        result['evidence_rows'] = sorted(
            [dict(row) for row in db.execute("SELECT * FROM advisory_evidence WHERE source='synology'")],
            key=canonical)
        result['manifest_rows'] = [dict(row) for row in db.execute(
            "SELECT * FROM manifests WHERE source='synology' ORDER BY resource")]
        result['event_keys'] = [row[0] for row in db.execute('SELECT key FROM events ORDER BY key')]
        result['quarantine_rows'] = [dict(row) for row in db.execute(
            "SELECT source_id,reason FROM quarantine WHERE source='synology' ORDER BY source_id")]
        result['retry_detail'] = [dict(row) for row in db.execute(
            "SELECT * FROM adapter_retries WHERE source='synology' ORDER BY resource")]
        result['request_trace'] = list(self.server.requests)
        result['requests'] = len(self.server.requests)
        return result

    def close(self):
        self.store._finalizer.detach()
        super().close()
