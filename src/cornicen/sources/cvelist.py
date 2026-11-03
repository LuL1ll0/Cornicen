"""CVE List releases: nested snapshot archives and cumulative daily deltas."""

from array import array
from bisect import bisect_right
import struct
from zlib import crc32
import zipfile as z


from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
import json
import logging
import re
import tempfile
import weakref
from zipfile import ZipFile, BadZipFile

from cornicen import validate
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.sources import CVE_ID, data_directory

RELEASES_URL = 'https://api.github.com/repos/CVEProject/cvelistV5/releases'
# Untrusted archive expansion budgets: 8 MiB per JSON, 4 GiB per snapshot.
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_RELEASE_PAGES = 50
COPY_CHUNK_BYTES = 1024 * 1024
RECORD_PATH = re.compile(r'(?:cves/\d{4}/[^/]+|deltaCves)/(CVE-\d{4}-\d{4,})\.json\Z')


class _SnapshotZip(z.ZipFile):
    def _RealGetContents(self):
        try:
            end = z._EndRecData(self.fp)
        except OSError:
            raise z.BadZipFile('File is not a zip file') from None
        if end is None:
            raise z.BadZipFile('File is not a zip file')
        self._comment = end[z._ECD_COMMENT]
        self._central_size = end[z._ECD_SIZE]
        location = end[z._ECD_LOCATION]
        # Python 3.11/3.12 report the ordinary EOCD location for ZIP64;
        # newer Python reports the ZIP64 EOCD itself. Inspect the signature.
        self.fp.seek(location)
        if end[z._ECD_SIGNATURE] == z.stringEndArchive64 and self.fp.read(4) == z.stringEndArchive:
            location -= z.sizeEndCentDir64 + z.sizeEndCentDir64Locator
        self.start_dir = location - self._central_size
        self._concat = self.start_dir - end[z._ECD_OFFSET]
        if self.start_dir < 0:
            raise z.BadZipFile('Bad offset for central directory')
        # Eight bytes per member retain overlap protection, including archives
        # whose central directory order differs from local-header order.
        offsets = array('Q', (entry.header_offset for entry in self._entries()))
        self._offsets = array('Q', sorted(offsets))
        if any(a == b for a, b in zip(self._offsets, self._offsets[1:])):
            raise z.BadZipFile('Overlapping ZIP member offsets')

    def _entries(self):
        position = self.start_dir
        end = position + self._central_size
        while position < end:
            self.fp.seek(position)
            header = self.fp.read(z.sizeCentralDir)
            if len(header) != z.sizeCentralDir:
                raise z.BadZipFile('Truncated central directory')
            fields = struct.unpack(z.structCentralDir, header)
            if fields[z._CD_SIGNATURE] != z.stringCentralDir:
                raise z.BadZipFile('Bad magic number for central directory')
            size = z.sizeCentralDir + sum(fields[index] for index in (
                z._CD_FILENAME_LENGTH, z._CD_EXTRA_FIELD_LENGTH, z._CD_COMMENT_LENGTH))
            if position + size > end:
                raise z.BadZipFile('Truncated central directory')
            filename = self.fp.read(fields[z._CD_FILENAME_LENGTH])
            encoding = 'utf-8' if fields[z._CD_FLAG_BITS] & 0x800 else self.metadata_encoding or 'cp437'
            entry = z.ZipInfo(filename.decode(encoding))
            entry.extra = self.fp.read(fields[z._CD_EXTRA_FIELD_LENGTH])
            entry.comment = self.fp.read(fields[z._CD_COMMENT_LENGTH])
            entry.header_offset = fields[z._CD_LOCAL_HEADER_OFFSET]
            (entry.create_version, entry.create_system, entry.extract_version, entry.reserved,
             entry.flag_bits, entry.compress_type, time, date, entry.CRC,
             entry.compress_size, entry.file_size) = fields[1:12]
            if entry.extract_version > z.MAX_EXTRACT_VERSION:
                raise NotImplementedError('Unsupported ZIP extraction version')
            entry.volume, entry.internal_attr, entry.external_attr = fields[15:18]
            entry._raw_time = time
            entry.date_time = ((date >> 9) + 1980, (date >> 5) & 15, date & 31,
                               time >> 11, (time >> 5) & 63, (time & 31) * 2)
            try:
                entry._decodeExtra(crc32(filename))
            except TypeError:
                entry._decodeExtra()  # Python 3.11/3.12.
            entry.header_offset += self._concat
            if not 0 <= entry.header_offset < self.start_dir:
                raise z.BadZipFile('Invalid local-header offset')
            position += size
            yield entry

    def infolist(self):
        for entry in self._entries():
            index = bisect_right(self._offsets, entry.header_offset)
            entry._end_offset = self._offsets[index] if index < len(self._offsets) else self.start_dir
            yield entry


class _Records(Sequence):
    """Replayable record sequence backed by an anonymous, automatically removed file.

    IngestResult's consumer only iterates records. Keeping the payload on disk
    preserves that interface without retaining hundreds of thousands of dicts.
    Call close() when discarding a result early; garbage collection also closes it.
    """

    def __init__(self, directory):
        self.file = tempfile.TemporaryFile(mode='w+t', encoding='utf-8', dir=directory)
        self.count = 0
        self._finalizer = weakref.finalize(self, self.file.close)

    def append(self, record):
        self.file.write(json.dumps(record, separators=(',', ':')) + '\n')
        self.count += 1

    def __len__(self):
        return self.count

    def __iter__(self):
        self.file.flush()
        self.file.seek(0)
        for line in self.file:
            yield json.loads(line)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple(self)[index]
        if index < 0:
            index += self.count
        for offset, record in enumerate(self):
            if offset == index:
                return record
        raise IndexError(index)

    def close(self):
        self._finalizer()


_stamp = validate.release_stamp

class CveListSource:
    def __init__(self, http, store):
        self.http, self.store = http, store
        self.directory = data_directory(http, store)

    def _get(self, url, now, allowed=(), **kwargs):
        response = self.http.get(url, source='cvelist', **kwargs)
        headers = {key.lower(): value for key, value in response.headers.items()}
        if response.status == 429 or (response.status == 403 and headers.get('x-ratelimit-remaining') == '0'):
            deadlines = []
            try:
                deadlines.append(datetime.fromtimestamp(float(headers.get('x-ratelimit-reset')), timezone.utc))
            except (ValueError, TypeError, OverflowError, OSError):
                pass
            retry_after = headers.get('retry-after', '')
            try:
                if retry_after.strip().isdigit():
                    deadlines.append(now + timedelta(seconds=int(retry_after)))
                else:
                    deadline = parsedate_to_datetime(retry_after)
                    deadlines.append(deadline if deadline.tzinfo else deadline.replace(tzinfo=timezone.utc))
            except (ValueError, TypeError, OverflowError):
                pass
            deadlines = [deadline for deadline in deadlines if deadline > now]
            retry = max(deadlines) if deadlines else now + timedelta(hours=1)
            previous = self.store.get_meta('github_retry_at')
            if previous:
                retry = max(retry, datetime.fromisoformat(previous))
            self.store.set_meta('github_retry_at', retry.isoformat())
        if response.status != 200 and response.status not in allowed:
            if response.path is not None:
                response.path.unlink(missing_ok=True)
            raise ValueError(f'HTTP {response.status}')
        return response

    def _listing(self, cursor, now):
        releases = []
        exhausted = False
        url = RELEASES_URL
        visited = set()
        if cursor:
            _stamp(cursor)
        while url:
            if url in visited:
                raise ValueError('Cyclic GitHub pagination')
            if len(visited) >= MAX_RELEASE_PAGES:
                raise ValueError('GitHub pagination page limit exceeded')
            visited.add(url)
            response = self._get(url, now, allowed=(422,))
            if response.status == 422:
                error = json.loads(response.body)
                if not isinstance(error, dict):
                    raise ValueError('GitHub error response is not an object')
                message = error.get('message')
                if not isinstance(message, str):
                    raise ValueError('GitHub error message is not a string')
                if 'Only the first 1000 results are available' in message:
                    break
                raise ValueError('HTTP 422: ' + validate.error_detail(message))
            page = json.loads(response.body)
            if not isinstance(page, list):
                raise ValueError('Release listing is not a list')
            for release in page:
                if not isinstance(release, dict):
                    raise ValueError('Invalid release')
                if release.get('draft') or release.get('prerelease'):
                    continue
                tag = release.get('tag_name')
                if not isinstance(tag, str) or not validate.TAG.fullmatch(tag):
                    logging.getLogger(__name__).warning('Skipping unrecognised release tag: %s', validate.error_detail(tag))
                    continue
                problems = validate.release(tag, release.get('assets'), release.get('published_at'), now)
                if problems:
                    raise ValueError('; '.join(problems))
                releases.append(release)
            match = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get('link', ''))
            url = match[1] if match else None
            exhausted = url is None
            # Bootstrap needs only page one. Catch-up cannot assume release
            # tags are ordered across pages, even after an older day appears.
            if cursor is None:
                break
        if not releases:
            raise ValueError('No CVE releases available')
        return releases, exhausted

    @staticmethod
    def _check_entry(entry, limit):
        if entry.file_size > limit:
            raise ValueError('Uncompressed size limit exceeded')
        if entry.file_size > MAX_COMPRESSION_RATIO * entry.compress_size:
            raise ValueError('Compression ratio limit exceeded')

    def _json_entry(self, zipped, entry):
        self._check_entry(entry, MAX_RECORD_BYTES)
        with zipped.open(entry) as stream:
            payload = stream.read(MAX_RECORD_BYTES + 1)
        if len(payload) > MAX_RECORD_BYTES:
            raise ValueError('Record size limit exceeded')
        return json.loads(payload)

    def _read_records(self, zipped, records, errors, snapshot):
        seen = set()
        decoded = set()
        manifests = []
        unrecognised_json = False
        expanded = 0
        root = 'cves/' if snapshot else 'deltaCves/'
        for entry in zipped.infolist():
            if snapshot and entry.filename in validate.SNAPSHOT_MANIFESTS:
                # These describe delta history, not snapshot coverage. Never
                # open them or apply record/expansion budgets to their contents.
                continue
            if snapshot:
                expanded += entry.file_size
                if expanded > MAX_SNAPSHOT_BYTES:
                    errors.append(f'{entry.filename}: Snapshot expansion limit exceeded')
                    break
            if entry.is_dir() or entry.filename.startswith(root):
                try:
                    self._check_entry(entry, MAX_RECORD_BYTES)
                    if entry.is_dir():
                        if snapshot and validate.SNAPSHOT_DIRECTORY.fullmatch(entry.filename):
                            continue
                        raise ValueError('Unexpected record path')
                    match = RECORD_PATH.fullmatch(entry.filename)
                    if not match:
                        raise ValueError('Unexpected record path')
                    record = self._json_entry(zipped, entry)
                    metadata = record.get('cveMetadata') if isinstance(record, dict) else None
                    if (not isinstance(metadata, dict) or not isinstance(metadata.get('cveId'), str)
                            or not CVE_ID.fullmatch(metadata['cveId']) or metadata['cveId'] != match[1]):
                        raise ValueError('Invalid CVE metadata or filename mismatch')
                    if metadata['cveId'] in seen:
                        raise ValueError('Duplicate CVE ID')
                    seen.add(metadata['cveId'])
                    problems = validate.record(record)
                    errors.extend(f'{entry.filename}: {problem}' for problem in problems)
                    if not problems:
                        decoded.add(metadata['cveId'])
                    # Invalid revisions travel to the engine's durable retry storage.
                    records.append(record)
                except Exception as error:
                    errors.append(f'{entry.filename}: {type(error).__name__}: {error}')
            elif not snapshot and entry.filename in ('deltaLog.json', 'delta.json'):
                try:
                    manifests.append(self._json_entry(zipped, entry))
                except Exception as error:
                    errors.append(f'{entry.filename}: {type(error).__name__}: {error}')
            elif snapshot:
                # Even unrelated snapshot entries count toward expansion and
                # must obey the ratio budget; their contents are never loaded.
                try:
                    self._check_entry(entry, MAX_SNAPSHOT_BYTES)
                except ValueError as error:
                    errors.append(f'{entry.filename}: {error}')
            elif entry.filename.endswith('.json'):
                unrecognised_json = True

        if not snapshot and not seen and unrecognised_json:
            errors.append('Unrecognised delta record layout')
        if not snapshot and (decoded or manifests or not errors):
            for manifest in manifests or [None]:
                errors.extend(validate.delta(manifest, decoded))

    def _archive(self, release, origin, now):
        snapshot = origin == Origin.SNAPSHOT
        path = None
        records = _Records(self.directory)
        errors = []
        try:
            asset, stamp = validate.release_asset(release['tag_name'], release['assets'], snapshot=snapshot)
            response = self._get(asset['browser_download_url'], now, to_file=True,
                                 budget='cvelist_snapshot' if snapshot else 'cvelist_delta')
            path = response.path
            if path is None:
                raise ValueError('Archive download has no file')
            with _SnapshotZip(path) as zipped:
                if snapshot:
                    inners = [entry for entry in zipped.infolist() if entry.filename.endswith('.zip')]
                    if len(inners) != 1:
                        raise ValueError('Snapshot must contain exactly one inner zip')
                    # Never extract using an archive path, including the inner
                    # zip's name. Both files are generated in the data directory.
                    self._check_entry(inners[0], MAX_SNAPSHOT_BYTES)
                    with tempfile.TemporaryFile(dir=self.directory) as inner:
                        with zipped.open(inners[0]) as stream:
                            copied = 0
                            while chunk := stream.read(min(COPY_CHUNK_BYTES, MAX_SNAPSHOT_BYTES - copied + 1)):
                                copied += len(chunk)
                                if copied > MAX_SNAPSHOT_BYTES:
                                    raise ValueError('Snapshot container size limit exceeded')
                                inner.write(chunk)
                        inner.seek(0)
                        with _SnapshotZip(inner) as record_zip:
                            self._read_records(record_zip, records, errors, True)
                else:
                    self._read_records(zipped, records, errors, False)
            if snapshot and not records and not errors:
                raise ValueError('Empty CVE snapshot')
            # The engine stores snapshot identity separately from delta coverage.
            cursor = release['tag_name']
            return IngestResult('cvelist', FetchStatus.PARTIAL if errors else FetchStatus.COMPLETE,
                                origin, cursor, stamp, records=records, errors=tuple(errors))
        except (OSError, HTTPException, EOFError, ValueError, TypeError, KeyError, BadZipFile, RecursionError) as error:
            errors.append(f'{type(error).__name__}: {error}')
            status = FetchStatus.PARTIAL if records else FetchStatus.FAILED
            return IngestResult('cvelist', status, origin, None, None,
                                records=records, errors=tuple(errors))
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    def poll(self, now):
        results = []
        deferred = self.store.get_meta('github_retry_at')
        if deferred and now < datetime.fromisoformat(deferred):
            return results
        try:
            row = self.store.connection.execute("SELECT value FROM cursors WHERE source='cvelist'").fetchone()
            cursor = row[0] if row else None
            if cursor and _stamp(cursor) > now + timedelta(hours=2):
                raise ValueError('Persisted CVE cursor is more than 2 hours in the future')
            cutoff = self.store.get_meta('cvelist_snapshot_cutoff')
            snapshot_complete = self.store.get_meta('cvelist_snapshot_complete')
            if cursor is None and snapshot_complete and cutoff:
                cursor = f'cve_{datetime.fromisoformat(cutoff):%Y-%m-%d}_0000Z'
            releases, listing_exhausted = self._listing(cursor, now)
            latest = max(releases, key=lambda r: _stamp(r['tag_name']))
            by_day = {}
            for release in sorted(releases, key=lambda r: _stamp(r['tag_name'])):
                by_day[_stamp(release['tag_name']).date()] = release
            reconcile = False
            if cursor:
                day = _stamp(cursor).date()
                while day <= _stamp(latest['tag_name']).date():
                    if day < now.date():
                        tag = f'cve_{day}_at_end_of_day'
                        # A listed EOD is already the exact desired release.
                        if by_day.get(day, {}).get('tag_name') != tag:
                            response = self._get(RELEASES_URL + '/tags/' + tag, now, allowed=(404,))
                            if response.status == 200:
                                release = json.loads(response.body)
                                if not isinstance(release, dict) or release.get('tag_name') != tag:
                                    raise ValueError('Unexpected direct-tag release')
                                problems = validate.release(tag, release.get('assets'), release.get('published_at'), now)
                                if problems:
                                    raise ValueError('; '.join(problems))
                                by_day[day] = release
                            elif not listing_exhausted:
                                reconcile = True
                                break
                    if day not in by_day:
                        reconcile = True
                        break
                    day += timedelta(days=1)
            if cursor is None or reconcile:
                if reconcile:
                    self.store.set_meta('reconcile_at', now.isoformat())
                pinned = self.store.get_meta('cvelist_snapshot_release') if not snapshot_complete else None
                snapshots = [r for r in releases if validate.release_assets(r['tag_name'], r['assets'], snapshot=True)]
                if pinned:
                    snapshot_release = next((r for r in snapshots if r['tag_name'] == pinned), None)
                    if snapshot_release is None:
                        snapshot_release = json.loads(self._get(RELEASES_URL + '/tags/' + pinned, now).body)
                        if not isinstance(snapshot_release, dict) or snapshot_release.get('tag_name') != pinned:
                            raise ValueError('Unexpected pinned snapshot release')
                        problems = validate.release(pinned, snapshot_release.get('assets'), snapshot_release.get('published_at'), now)
                        if problems:
                            raise ValueError('; '.join(problems))
                else:
                    if not snapshots:
                        raise ValueError('No full snapshot asset available')
                    snapshot_release = max(snapshots, key=lambda r: _stamp(r['tag_name']))
                if reconcile and _stamp(snapshot_release['tag_name']).date() <= day:
                    raise ValueError(f'No full snapshot cutoff covers {day}')
                snapshot = self._archive(snapshot_release, Origin.SNAPSHOT, now)
                results.append(snapshot)
                if snapshot.status != FetchStatus.COMPLETE:
                    return results
                # A resumed partial snapshot may predate page one. Its deltas
                # are caught up from the durable cutoff on the following poll.
                chosen = [r for day, r in sorted(by_day.items()) if day == _stamp(snapshot_release['tag_name']).date()]
            else:
                chosen = [r for day, r in sorted(by_day.items()) if _stamp(r['tag_name']) > _stamp(cursor)]

            def delta_order(candidate):
                return (validate.release_asset(candidate['tag_name'], candidate['assets'])[1],
                        _stamp(candidate['tag_name']))

            for release in chosen:
                # The newest tag must be complete. Older incomplete releases
                # cannot block it, since each daily delta is cumulative.
                # Asset times order coverage; tags identify releases and break ties.
                order = delta_order(release)
                for candidate in releases:
                    if _stamp(candidate['tag_name']).date() != order[0].date():
                        continue
                    try:
                        candidate_order = delta_order(candidate)
                    except ValueError:
                        continue
                    if candidate_order > order:
                        release, order = candidate, candidate_order
                if cursor and not reconcile and _stamp(release['tag_name']) <= _stamp(cursor):
                    continue
                result = self._archive(release, Origin.DELTA, now)
                results.append(result)
                # A later complete ingest must never move the cursor past an
                # earlier incomplete day in the same engine cycle.
                if result.status != FetchStatus.COMPLETE:
                    break
            return results
        except (OSError, HTTPException, ValueError, TypeError, KeyError, RecursionError) as error:
            results.append(IngestResult('cvelist', FetchStatus.FAILED, Origin.DELTA, None, None,
                                        errors=(f'{type(error).__name__}: {error}',)))
            return results
