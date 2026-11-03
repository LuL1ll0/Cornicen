"""Bulk public-feed adapters. Sources never advance engine-owned cursors."""

from pathlib import Path
from cornicen.validate import CVE_ID


def data_directory(http, store):
    """The configured database lives in the data directory; memory stores use Http's setting."""
    path = store.connection.execute('PRAGMA database_list').fetchone()[2]
    if path:
        http.data_dir = Path(path).parent
    return http.data_dir
