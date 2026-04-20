"""Block iteration helpers including continuation merging."""

import logging
from typing import Iterator, Tuple

from .enums import BlockFlag
from .types import MslBlockHeader

logger = logging.getLogger("memdiver.msl.block_iter")


def merge_continuations(
    blocks: Iterator[Tuple[MslBlockHeader, bytes]],
) -> Iterator[Tuple[MslBlockHeader, bytes]]:
    """Merge continuation blocks with their parent.

    Continuation blocks (CONTINUATION flag) have their payload appended
    to the parent block (identified by parent_uuid). The merged result
    is yielded under the parent's header.

    Non-continuation blocks are yielded immediately if they have no
    pending continuations.
    """
    pending = {}  # parent_uuid -> (parent_hdr, [payloads])

    for hdr, payload in blocks:
        is_continuation = bool(hdr.flags & BlockFlag.CONTINUATION)
        has_children = bool(hdr.flags & BlockFlag.HAS_CHILDREN)

        if is_continuation:
            key = hdr.parent_uuid
            if key in pending:
                pending[key][1].append(payload)
            else:
                logger.warning(
                    "Orphaned continuation block at 0x%X (parent %s)",
                    hdr.file_offset, hdr.parent_uuid,
                )
                yield hdr, payload
        else:
            # Flush all completed parents before yielding current block.
            if pending:
                completed = [
                    uuid for uuid in pending
                    if uuid != hdr.block_uuid
                ]
                for uuid in completed:
                    parent_hdr, payloads = pending.pop(uuid)
                    yield parent_hdr, b"".join(payloads)
            if has_children:
                pending[hdr.block_uuid] = (hdr, [payload])
            else:
                yield hdr, payload

    # Yield any remaining pending blocks at end of stream.
    for parent_hdr, payloads in pending.values():
        yield parent_hdr, b"".join(payloads)
