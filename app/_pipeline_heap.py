"""Heap-role plumbing shared by the pipeline producers in ``tools_pipeline``.

The consensus stage persists ``cm.heap`` as ``heap_roles.npz`` beside
``variance.npy`` plus a ``"heap"`` block in ``consensus.json``; the reduce
stages (``search_reduce`` / ``analyze_candidates``) read it back and hand it to
:func:`memdiver.engine.candidate_pipeline.reduce_search_space` under a
``heap_policy``. Engine imports stay function-local, as everywhere in ``app``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Artifact the consensus stage writes beside ``variance.npy``.
HEAP_ROLES_FILENAME = "heap_roles.npz"

#: ``(heap_runs, heap_chunks)`` as ``reduce_search_space`` takes them.
HeapInputs = Tuple[Optional[Any], Optional[Any]]

_NO_HEAP: HeapInputs = (None, None)


def checked_heap_policy(heap_policy: str) -> str:
    """Reject an unknown ``heap_policy`` as INVALID_INPUT."""
    from memdiver.engine.candidate_pipeline import HEAP_POLICIES

    if heap_policy not in HEAP_POLICIES:
        raise CapabilityError(
            f"heap_policy={heap_policy!r} is not one of {HEAP_POLICIES}",
            category=ErrorCategory.INVALID_INPUT,
        )
    return heap_policy


def _mask_unavailable(reason: str) -> CapabilityError:
    return CapabilityError(
        f"heap_policy='mask' needs consensus heap roles, but {reason}. "
        f"Rebuild the consensus with an allocator other than 'off', or use "
        f"heap_policy='annotate' / 'off'.",
        category=ErrorCategory.PRECONDITION,
    )


def write_consensus_heap(heap: Optional[Any], out_dir: Path) -> Optional[Dict[str, Any]]:
    """Persist ``cm.heap``; return the ``"heap"`` block for ``consensus.json``.

    ``heap_roles.npz`` is written only for a usable (``status == "ok"``)
    annotation, so a later ``mask`` never silently masks with an empty map.
    Otherwise a ``heap_roles.npz`` left by an earlier build in *out_dir* is
    removed: it would describe a different consensus. ``None`` (allocator
    "off") returns ``None`` — no block.
    """
    from memdiver.engine.consensus_heap import STATUS_OK, save_heap_npz

    path = out_dir / HEAP_ROLES_FILENAME
    if heap is None or heap.status != STATUS_OK:
        path.unlink(missing_ok=True)
    if heap is None:
        return None
    block: Dict[str, Any] = {"status": heap.status, **heap.to_dict(),
                             "heap_roles_path": None}
    if heap.status == STATUS_OK:
        save_heap_npz(heap, path)
        block["heap_roles_path"] = str(path)
    return block


def load_heap_beside(variance_path: str, heap_policy: str) -> HeapInputs:
    """Heap inputs for a reduce over ``variance_path`` (its sibling npz).

    No npz: ``(None, None)`` — the reduction then behaves as ``"off"`` — except
    under an explicit ``"mask"``, which is a PRECONDITION error.
    """
    if heap_policy == "off":
        return _NO_HEAP
    path = Path(variance_path).parent / HEAP_ROLES_FILENAME
    if not path.is_file():
        if heap_policy == "mask":
            raise _mask_unavailable(f"no {HEAP_ROLES_FILENAME} beside {variance_path}")
        return _NO_HEAP
    from memdiver.engine.consensus_heap import load_heap_npz

    return load_heap_npz(path)


def heap_inputs_from_consensus(cm: Any, heap_policy: str) -> HeapInputs:
    """Heap inputs from an in-memory consensus (same rules as the npz path)."""
    if heap_policy == "off":
        return _NO_HEAP
    from memdiver.engine.consensus_heap import STATUS_OK

    heap = getattr(cm, "heap", None)
    if heap is None or heap.status != STATUS_OK:
        if heap_policy == "mask":
            status = "allocator='off'" if heap is None else f"status={heap.status!r}"
            raise _mask_unavailable(f"the consensus heap annotation is unavailable ({status})")
        return _NO_HEAP
    return heap.runs, heap.chunks


def allocator_for_policy(allocator: str, heap_policy: str) -> str:
    """``"off"`` when the policy ignores heap roles (skip the analysis cost)."""
    return "off" if heap_policy == "off" else allocator
