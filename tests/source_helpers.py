"""Offline HTTP and archive builders for source tests."""

from copy import deepcopy
import io
import json
from pathlib import Path
import socket
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_STORED

RAW = Path(__file__).parent / 'fixtures' / 'raw'


def public_resolver(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
             ('93.184.216.34', port))]


class Reply(io.BytesIO):
    def __init__(self, body=b'', status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}


class Opener:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if '/releases/tags/' in request.full_url and request.full_url not in self.routes:
            return Reply(b'{"message":"Not Found"}', 404)
        value = self.routes[request.full_url]
        if isinstance(value, Exception):
            raise value
        body, status, headers = value if isinstance(value, tuple) else (value, 200, {})
        return Reply(body, status, headers)


def archive(count=1, snapshot=False, bad=False, errors=False, padding=0):
    record = json.loads((RAW / 'CVE-2026-106803.json').read_text())
    buffer = io.BytesIO()
    # Store snapshot records uncompressed so loading the whole inner zip would
    # exceed the memory limit. The outer container also uses stored entries.
    with ZipFile(buffer, 'w', ZIP_STORED if snapshot else ZIP_DEFLATED) as zipped:
        for n in range(count):
            record['cveMetadata']['cveId'] = f'CVE-2026-{10000+n}'
            record['padding'] = 'x' * padding
            root = 'cves/2026/10xxx' if snapshot else 'deltaCves'
            zipped.writestr(f'{root}/CVE-2026-{10000+n}.json', json.dumps(record))
        if bad:
            zipped.writestr(f'{root}/CVE-2026-99999.json', '{broken')
            zipped.writestr(f'{root}/CVE-2026-99998.json', '{"cveMetadata": []}')
            zipped.writestr('../../escape.json', '{}')
        if errors:
            zipped.writestr('deltaLog.json', json.dumps({'error': ['CVE-2026-88888']}))
    if snapshot:
        outer = io.BytesIO()
        # Keep synthetic repeated padding below the container ratio limit.
        # The inner zip remains large, preserving the streaming memory check.
        with ZipFile(outer, 'w', ZIP_STORED) as zipped:
            zipped.writestr('all_CVEs_at_midnight.zip', buffer.getvalue())
        return outer.getvalue()
    return buffer.getvalue()


def release(day, hour=23):
    tag = f'cve_2026-11-{day:02d}_{hour:02d}00Z'
    return {'tag_name': tag, 'assets': [
        {'name': f'2026-11-{day:02d}_all_CVEs_at_midnight.zip.zip',
         'browser_download_url': f'https://github.com/{tag}/snapshot'},
        {'name': f'2026-11-{day:02d}_delta_CVEs_at_{hour:02d}00Z.zip',
         'browser_download_url': f'https://github.com/{tag}/delta'}]}


def expected_projection(record):
    # Independent contract: named subtrees survive exactly; all other data goes.
    result = {'cveMetadata': deepcopy(record['cveMetadata'])}
    containers = record.get('containers', {})
    projected = {}
    if 'cna' in containers:
        cna = containers['cna']
        projected['cna'] = {key: deepcopy(cna[key]) for key in ('affected', 'title') if key in cna}
        if 'shortName' in cna.get('providerMetadata', {}):
            projected['cna']['providerMetadata'] = {'shortName': cna['providerMetadata']['shortName']}
    for name, sources in (('cna', [containers['cna']] if 'cna' in containers else []),
                          ('adp', containers.get('adp', []))):
        targets = [projected['cna']] if name == 'cna' and sources else []
        if name == 'adp' and 'adp' in containers:
            projected['adp'] = targets = [{} for _ in sources]
        for source, target in zip(sources, targets):
            if 'metrics' in source:
                target['metrics'] = [{key: deepcopy(value) for key, value in metric.items()
                                      if key.startswith('cvss')} for metric in source['metrics']]
    if 'containers' in record:
        result['containers'] = projected
    return result
