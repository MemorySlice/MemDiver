"""DumpSearcher - search binary dump files for key bytes."""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from .models import TLSSecret, KeyOccurrence

logger = logging.getLogger("memdiver.dump_search")


class DumpSearcher:
    """Search binary dump files for key bytes."""

    def __init__(self, dump_path: Path):
        self.path = dump_path
        self.data: Optional[bytes] = None

    def load(self) -> None:
        with open(self.path, "rb") as f:
            self.data = f.read()

    def find_all(self, needle: bytes) -> List[int]:
        if self.data is None:
            self.load()
        offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    def extract_context(self, offset: int, key_len: int, ctx: int = 0x100) -> Tuple[bytes, bytes, bytes]:
        if self.data is None:
            self.load()
        file_len = len(self.data)

        before_start = max(0, offset - ctx)
        before = self.data[before_start:offset]
        if len(before) < ctx:
            before = b'\x00' * (ctx - len(before)) + before

        key_bytes = self.data[offset:offset + key_len]

        after_end = min(file_len, offset + key_len + ctx)
        after = self.data[offset + key_len:after_end]
        if len(after) < ctx:
            after = after + b'\x00' * (ctx - len(after))

        return before, key_bytes, after

    def search_secrets(self, secrets: List[TLSSecret], ctx: int = 0x100) -> List[KeyOccurrence]:
        if self.data is None:
            self.load()
        occurrences = []
        for secret in secrets:
            offsets = self.find_all(secret.secret_value)
            for offset in offsets:
                before, key_bytes, after = self.extract_context(offset, len(secret.secret_value), ctx)
                occurrences.append(KeyOccurrence(
                    offset=offset,
                    secret=secret,
                    context_before=before,
                    key_bytes=key_bytes,
                    context_after=after,
                ))
        return occurrences
