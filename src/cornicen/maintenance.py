"""Local SQLite maintenance without migrations or source writes."""

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile


def backup(source, output):
    """Copy a live read-only connection, then atomically publish without replacement."""
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError('Backup destination exists; choose a new output path')
    fd, name = tempfile.mkstemp(prefix='.' + output.name + '-', suffix='.staging',
                                dir=output.parent)
    staging = Path(name)
    try:
        os.fchmod(fd, 0o600)
        os.close(fd)
        fd = None
        # Use rollback journaling on the copy so the published file stands alone.
        with closing(sqlite3.connect(staging)) as target:
            source.backup(target)
            target.execute('PRAGMA journal_mode=DELETE')
            if target.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise sqlite3.DatabaseError('Backup quick_check failed')
        with staging.open('rb') as copied:
            os.fsync(copied.fileno())
        os.link(staging, output)
    finally:
        if fd is not None:
            os.close(fd)
        staging.unlink()
