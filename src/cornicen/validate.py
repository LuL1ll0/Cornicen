"""Feed boundary contracts. Problems mean incomplete coverage, never empty success."""

from datetime import datetime, timedelta, timezone
import math
import re
import unicodedata

CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}\Z')
TAG = re.compile(r'cve_(\d{4}-\d{2}-\d{2})_(?:(\d{2})00Z|at_end_of_day)\Z')
DELTA_ASSET = re.compile(r'(\d{4}-\d{2}-\d{2})_delta_CVEs_at_(\d{4}Z|end_of_day)\.zip\Z')
SNAPSHOT_ASSET = re.compile(r'(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip\.zip\Z')
SNAPSHOT_DIRECTORY = re.compile(r'cves/(\d{4}/(\d+xxx/)?)?\Z')
SNAPSHOT_MANIFESTS = ('cves/delta.json', 'cves/deltaLog.json')


def error_detail(value):
    return ''.join(c for c in str(value) if not unicodedata.category(c).startswith('C'))[:200]


def record(value) -> list[str]:
    problems = []
    if not isinstance(value, dict):
        return ['CVE record must be an object']
    metadata = value.get('cveMetadata')
    if not isinstance(metadata, dict):
        return ['cveMetadata must be an object']
    if not isinstance(metadata.get('cveId'), str) or not CVE_ID.fullmatch(metadata['cveId']):
        problems.append('Invalid cveMetadata.cveId')
    for field in ('datePublished', 'dateUpdated'):
        if field in metadata:
            date_value = metadata[field]
            try:
                if not isinstance(date_value, str) or not re.match(r'^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}', date_value):
                    raise ValueError('Timestamp string required')
                timestamp(date_value)
            except (ValueError, TypeError):
                problems.append('Invalid cveMetadata.' + field + ': timestamp string required')
    if metadata.get('state') not in ('PUBLISHED', 'REJECTED'):
        problems.append('Invalid cveMetadata.state')
    if metadata.get('state') != 'PUBLISHED':
        return problems
    containers = value.get('containers')
    cna = containers.get('cna') if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        return problems + ['containers.cna must be an object']

    def objects(parent, key, path):
        values = parent.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
            problems.append(path + ' must be a list of objects')
            return []
        return values

    def strings(parent, keys, path):
        for key in keys:
            if key in parent and not isinstance(parent[key], str):
                problems.append(path + '.' + key + ' must be a string')

    for affected in objects(cna, 'affected', 'affected'):
        strings(affected, ('vendor', 'product', 'defaultStatus'), 'affected')
        for version in objects(affected, 'versions', 'versions'):
            for key in ('version', 'status'):
                if key not in version:
                    problems.append('versions.' + key + ' is required')
            strings(version, ('version', 'status', 'versionType', 'lessThan', 'lessThanOrEqual'), 'versions')
            for change in objects(version, 'changes', 'changes'):
                for key in ('at', 'status'):
                    if key not in change:
                        problems.append('changes.' + key + ' is required')
                strings(change, ('at', 'status'), 'changes')
    return problems


def delta(manifest, decoded_ids) -> list[str]:
    if manifest is None:
        return [] if decoded_ids else ['Delta has no recognised records or explicit zero-change manifest']
    if not isinstance(manifest, dict):
        return ['Delta manifest must be an object']
    problems, declared = [], set()
    for kind in ('new', 'updated'):
        entries = manifest.get(kind)
        if not isinstance(entries, list):
            problems.append('Delta manifest ' + kind + ' must be a list')
            continue
        for entry in entries:
            key = entry.get('cveId') if isinstance(entry, dict) else entry
            if not isinstance(key, str) or not CVE_ID.fullmatch(key):
                problems.append('Invalid declared CVE ID in ' + kind)
            else:
                declared.add(key)
    errors = manifest.get('error', [])
    if not isinstance(errors, list) or errors:
        problems.append('Delta manifest error: ' + str(errors))
    problems.extend('Declared record missing or invalid: ' + key for key in sorted(declared - set(decoded_ids)))
    return problems


def release_stamp(tag):
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if not match:
        raise ValueError('Unrecognised CVE release tag')
    day, hour = match.groups()
    stamp = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    if hour is None:
        return stamp.replace(hour=23, minute=59, second=59)
    return stamp.replace(hour=int(hour))


def release_assets(tag, assets, *, snapshot=False):
    pattern = SNAPSHOT_ASSET if snapshot else DELTA_ASSET
    day = release_stamp(tag).date().isoformat()
    return [asset for asset in assets
            if (match := pattern.fullmatch(asset['name'])) and match[1] == day]


def release_asset(tag, assets, *, snapshot=False):
    """Select one same-day archive and its coverage time, retaining tag identity."""
    matches = release_assets(tag, assets, snapshot=snapshot)
    kind = 'snapshot' if snapshot else 'delta'
    if not matches:
        raise ValueError(f'{tag}: Required release asset missing ({kind}, same date)')
    if len(matches) != 1:
        raise ValueError(f'{tag}: Expected exactly one {kind} release asset; found {len(matches)}')
    asset = matches[0]
    tag_stamp = release_stamp(tag)
    stamp = tag_stamp.replace(hour=0, minute=0, second=0)
    if not snapshot:
        clock = DELTA_ASSET.fullmatch(asset['name'])[2]
        if clock == 'end_of_day':
            stamp = stamp.replace(hour=23, minute=59, second=59)
        else:
            try:
                stamp = stamp.replace(hour=int(clock[:2]), minute=int(clock[2:4]))
            except ValueError:
                raise ValueError(f'{tag}: Invalid delta asset time: {asset["name"]}') from None
        if abs(stamp - tag_stamp) > timedelta(hours=2):
            raise ValueError(f'{tag}: delta asset time differs from tag by more than 2 hours: {asset["name"]}')
    return asset, stamp


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def release(tag, assets, published_at, now) -> list[str]:
    try:
        stamp = release_stamp(tag)
        if stamp > now + timedelta(hours=2):
            return [f'{tag}: release tag is more than 2 hours in the future']
        if published_at is not None and timestamp(published_at) > now + timedelta(hours=2):
            return [f'{tag}: published_at is more than 2 hours in the future']
    except (ValueError, TypeError, AttributeError):
        return [f'{tag}: invalid release timestamp']
    if not isinstance(assets, list) or any(not isinstance(a, dict) or not all(
            isinstance(a.get(k), str) and a[k] for k in ('name', 'browser_download_url')) for a in assets):
        return [f'{tag}: invalid release assets']
    return []


def kev(catalog, now) -> list[str]:
    if (not isinstance(catalog, dict) or not isinstance(catalog.get('catalogVersion'), str)
            or not catalog['catalogVersion'].strip() or not isinstance(catalog.get('dateReleased'), str)
            or type(catalog.get('count')) is not int):
        return ['Invalid KEV catalog metadata']
    entries = catalog.get('vulnerabilities')
    if not isinstance(entries, list) or not entries or len(entries) != catalog['count']:
        return ['Empty catalog or count mismatch']
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not isinstance(entry.get('cveID'), str)
                or not CVE_ID.fullmatch(entry['cveID']) or not all(
                    isinstance(entry.get(k), str) and entry[k].strip() for k in ('vendorProject', 'product'))):
            return ['Invalid KEV entry']
        if entry['cveID'] in seen:
            return ['Duplicate KEV entry']
        seen.add(entry['cveID'])
    try:
        if timestamp(catalog['dateReleased']) > now + timedelta(hours=2):
            return ['KEV dateReleased is more than 2 hours in the future']
    except (ValueError, TypeError):
        return ['Invalid KEV dateReleased']
    return []


def epss(scores, score_date, previous_date, previous_count, now) -> list[str]:
    if not scores:
        return ['Empty EPSS file']
    if previous_date and score_date < previous_date:
        return ['EPSS score date regressed']
    if score_date > (now + timedelta(hours=2)).date():
        return ['EPSS score date is in the future']
    if len(scores) * 5 < previous_count * 4:
        return ['EPSS row count dropped more than 20%']
    if any(not CVE_ID.fullmatch(key) or not all(math.isfinite(v) and 0 <= v <= 1 for v in values)
           for key, values in scores.items()):
        return ['Invalid EPSS score']
    return []
