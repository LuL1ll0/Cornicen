"""Durable JSONL delivery for local dry runs."""

from dataclasses import asdict
import json
import os
from pathlib import Path


class FileNotifier:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.exists():
            self.path.chmod(0o600)

    def send(self, n):
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(json.dumps(asdict(n), ensure_ascii=False) + '\n')
                target.flush()
                os.fsync(target.fileno())
            return True
        except (OSError, ValueError, TypeError):
            return False
