# script-purpose: Map OSV records into feed members without performing I/O.
# script-class: pipeline-tool
# script-trigger: OSV record normalization.
# script-tests: tests/test_task4_a.py
"""Read OSV dictionaries and return feed dictionaries; write nothing.

Library API, no process exit codes. Invalid records return mapping_error members.
"""
from hashlib import sha256
import json
import re

from cornicen import feeddates
from cornicen.feedvalidate import display_url

OSV_SCHEMES = {'Debian': 'debian'}
OSV_SOURCES = frozenset({'debian'})
EVENTS = frozenset({'introduced', 'fixed', 'last_affected', 'limit'})


def ecosystem_scheme(name):
    return next((scheme for key, scheme in OSV_SCHEMES.items()
                 if name == key or name.startswith(key + ':')), None)


def range_shape(value):
    """Validate syntax only; event ordering belongs to evaluation."""
    return (isinstance(value, dict) and isinstance(value.get('ranges'), list)
            and isinstance(value.get('versions'), list)
            and all(isinstance(v, str) and bool(v) for v in value['versions'])
            and all(isinstance(r, dict) and isinstance(r.get('type'), str)
                    and isinstance(r.get('events'), list)
                    and all(isinstance(e, dict) and len(e) == 1
                            and next(iter(e)) in EVENTS
                            and isinstance(next(iter(e.values())), str)
                            and bool(next(iter(e.values()))) for e in r['events'])
                    for r in value['ranges']))


def normalise(record):
    identity = record.get('id') if isinstance(record, dict) else None
    if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}', identity):
        return dict(id=None, mapping_error='invalid OSV id', osv_digest=sha256(
            json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest())
    def error(message):
        return dict(id=identity, mapping_error=message)
    try:
        for key in ('modified', 'published', 'withdrawn'):
            if record.get(key) is not None:
                feeddates.rfc3339(record[key])
            elif key == 'modified':
                raise ValueError
    except (ValueError, TypeError):
        return error('invalid OSV date')
    if 'details' in record and (not isinstance(record['details'], str)
            or len(record['details']) > 65536 or '\0' in record['details']):
        return error('invalid OSV details')
    affected = record.get('affected', [])
    if not isinstance(affected, list) or (not affected and not record.get('withdrawn')):
        return error('invalid OSV affected')
    products, evidence, urls = [], [], []
    for n, entry in enumerate(affected):
        package = entry.get('package') if isinstance(entry, dict) else None
        if not isinstance(package, dict) or any(not isinstance(package.get(k), str)
                or not package[k] or '#' in package[k] for k in ('ecosystem', 'name')):
            return error('invalid OSV package')
        bounds = dict(ranges=entry.get('ranges', []), versions=entry.get('versions', []))
        if not range_shape(bounds) or not (bounds['ranges'] or bounds['versions']):
            return error('invalid OSV ranges or versions')
        product = dict(id=f'aff-{n}', name=f"osv-selector:{package['ecosystem']}#{package['name']}")
        if isinstance(package.get('purl'), str):
            product['purl'] = package['purl']
        products.append(product)
        evidence.append(dict(product_id=product['id'], status='known_affected',
            scheme=ecosystem_scheme(package['ecosystem']) or 'opaque',
            range=dict(osv=json.dumps(bounds, sort_keys=True, separators=(',', ':'), ensure_ascii=False))))
        database = entry.get('database_specific')
        if isinstance(database, dict):
            urls.append(database.get('source'))
    references = record.get('references', [])
    urls = [r.get('url') for r in references if isinstance(r, dict) and r.get('type') == 'ADVISORY'] + urls if isinstance(references, list) else urls
    url = f'https://osv.dev/vulnerability/{identity}'
    for candidate in urls:
        try:
            url = display_url(candidate)
            break
        except ValueError:
            pass
    cves = []
    values = [identity]
    for key in ('upstream', 'aliases'):
        if isinstance(record.get(key), list):
            values.extend(record[key])
    for value in values:
        if isinstance(value, str):
            value = value.removeprefix('DEBIAN-')
            if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', value) and value not in cves:
                cves.append(value)
    result = dict(id=identity, title=record.get('summary') if isinstance(record.get('summary'), str)
                  and record['summary'].strip() else identity, url=url, cves=cves,
                  products=products, evidence=evidence, updated=record['modified'])
    for key in ('published', 'withdrawn', 'details'):
        if key in record:
            result[key] = record[key]
    return result
