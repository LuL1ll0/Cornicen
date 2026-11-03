"""CISA's full known-exploited-vulnerabilities catalog."""

from datetime import datetime, timezone
from http.client import HTTPException
import json

from cornicen import validate
from cornicen.model import FetchStatus, IngestResult, Origin

URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


class KevSource:
    def __init__(self, http):
        self.http = http
        self.etag = self.modified = None
        self.accepted = None

    def poll(self, now):
        try:
            response = self.http.get(URL, self.etag, self.modified, source='kev')
            if response.status == 304 and self.accepted is not None:
                # Engine's catalog interface is a full replacement, so retain the
                # accepted map rather than turning a 304 into a catalog deletion.
                return [self.accepted]
            if response.status != 200:
                raise ValueError(f'HTTP {response.status}')
            catalog = json.loads(response.body)
            problems = validate.kev(catalog, now)
            if problems:
                raise ValueError('; '.join(problems))
            result = {entry['cveID']: entry for entry in catalog['vulnerabilities']}
            cursor = catalog['catalogVersion']
            content_time = datetime.fromisoformat(catalog['dateReleased'].replace('Z', '+00:00'))
            if content_time.tzinfo is None:
                content_time = content_time.replace(tzinfo=timezone.utc)
            ingest = IngestResult('kev', FetchStatus.COMPLETE, Origin.CATALOG,
                                  cursor, content_time, kev=result)
            self.etag = response.headers.get('etag')
            self.modified = response.headers.get('last-modified')
            self.accepted = ingest
            return [ingest]
        except (OSError, HTTPException, ValueError, TypeError, KeyError, RecursionError) as error:
            return [IngestResult('kev', FetchStatus.FAILED, Origin.CATALOG, None, None,
                                 errors=(f'{type(error).__name__}: {error}',))]
