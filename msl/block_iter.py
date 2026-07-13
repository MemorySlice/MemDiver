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

    The MSL framing carries no explicit "last continuation" marker, so a
    parent stays pending until end-of-stream rather than being flushed the
    moment an unrelated block arrives. This means a parent whose
    continuation stream is interrupted by an unrelated block (non-contiguous
    producers) still has its trailing continuations merged correctly instead
    of being split off as orphans. ``pending`` preserves insertion order, so
    parents are emitted in their original arrival order at end-of-stream.
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
        elif has_children:
            # A parent re-using a still-pending uuid finalizes the prior one.
            if hdr.block_uuid in pending:
                prev_hdr, prev_payloads = pending.pop(hdr.block_uuid)
                yield prev_hdr, b"".join(prev_payloads)
            pending[hdr.block_uuid] = (hdr, [payload])
        else:
            # Unrelated leaf blocks pass through immediately, but pending
            # parents are NOT dropped here: their continuations may still
            # arrive after this block (non-contiguous producers).
            yield hdr, payload

    # Yield any remaining pending blocks at end of stream, in arrival order.
    for parent_hdr, payloads in pending.values():
        yield parent_hdr, b"".join(payloads)
