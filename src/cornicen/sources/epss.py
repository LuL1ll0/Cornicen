"""FIRST bulk scores, validated before replacing the accepted score map."""

import csv
from datetime import date, datetime, time, timezone
from http.client import HTTPException
import gzip
import re
import zlib

from cornicen import validate
from cornicen.model import FetchStatus, IngestResult, Origin
from cornicen.sources import data_directory

URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
# Bound each expanded metadata/CSV line before handing it to the parsers.
MAX_LINE_CHARS = 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ROWS = 2_000_000
MAX_CVE_ID_CHARS = 32
CVE_ID = re.compile(r'CVE-\d{4}-\d{4,19}', re.ASCII)


def _lines(stream):
    expanded = 0
    while line := stream.readline(min(MAX_LINE_CHARS, MAX_EXPANDED_BYTES - expanded) + 1):
        expanded += len(line)
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError('EPSS expanded byte limit exceeded')
        if len(line) > MAX_LINE_CHARS:
            raise ValueError('EPSS line size limit exceeded')
        yield line.decode('utf-8')


class EpssSource:
    def __init__(self, http, store):
        self.http, self.store = http, store
        data_directory(http, store)

    def poll(self, now):
        path = None
        try:
            response = self.http.get(URL, source='epss', to_file=True)
            path = response.path
            if response.status != 200 or path is None:
                raise ValueError(f'HTTP {response.status}')
            with gzip.open(path, 'rb') as stream:
                lines = _lines(stream)
                metadata = next(lines, '').strip()
                if not metadata.startswith('#model_version:'):
                    raise ValueError('Missing EPSS metadata')
                fields = dict(field.split(':', 1) for field in metadata[1:].split(','))
                stamp = datetime.fromisoformat(fields['score_date'].replace('Z', '+00:00'))
                score_date = stamp.date()
                previous = self.store.connection.execute(
                    "SELECT value FROM cursors WHERE source='epss'").fetchone()
                reader = csv.reader(lines, strict=True)
                if next(reader, None) != ['cve', 'epss', 'percentile']:
                    raise ValueError('Invalid EPSS columns')
                scores = {}
                for count, row in enumerate(reader, 1):
                    if count > MAX_ROWS:
                        raise ValueError('EPSS row count limit exceeded')
                    if (len(row) != 3 or len(row[0]) > MAX_CVE_ID_CHARS
                            or not CVE_ID.fullmatch(row[0]) or row[0] in scores):
                        raise ValueError('Invalid or duplicate EPSS row')
                    values = (float(row[1]), float(row[2]))
                    scores[row[0]] = values
                # Reading to EOF above also verifies gzip's trailer and CRC.
            counts = [int(value) for key in ('last_epss_row_count', 'last_epss_rows')
                      if (value := self.store.get_meta(key)) is not None]
            problems = validate.epss(scores, score_date,
                date.fromisoformat(previous[0]) if previous and previous[0] else None,
                max(counts, default=0), now)
            if problems:
                raise ValueError('; '.join(problems))
            return [IngestResult('epss', FetchStatus.COMPLETE, Origin.SCORES,
                                 score_date.isoformat(), datetime.combine(score_date, time(), timezone.utc),
                                 epss=scores, epss_date=score_date)]
        except (OSError, HTTPException, EOFError, ValueError, TypeError, KeyError, csv.Error, zlib.error) as error:
            return [IngestResult('epss', FetchStatus.FAILED, Origin.SCORES, None, None,
                                 errors=(f'{type(error).__name__}: {error}',))]
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
