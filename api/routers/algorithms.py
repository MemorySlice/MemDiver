"""HTTP surface for algorithm availability gating.

Thin presenter over :func:`memdiver.app.tools_algorithms.algorithm_availability`
so the "which algorithms can run + why not" logic lives server-side once,
instead of being duplicated in the frontend.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query

from memdiver.app.tools_algorithms import algorithm_availability

router = APIRouter()


@router.get("/availability")
def get_algorithm_availability(
    dump_count: int = 0,
    has_keylog: bool = False,
    has_candidate_keys: bool = False,
    algorithms: Optional[List[str]] = Query(default=None),
    mode: Optional[str] = None,
):
    """Return which algorithms can run given the current inputs, and why not.

    ``algorithms`` is a repeatable query param naming the algorithms to
    evaluate; when omitted only the gated algorithms are returned (every other
    name is available by default). ``mode`` mirrors the frontend's unused
    ``inputMode`` context field and is ignored.
    """
    return {
        "availability": algorithm_availability(
            dump_count=dump_count,
            has_keylog=has_keylog,
            has_candidate_keys=has_candidate_keys,
            algorithms=algorithms,
            mode=mode,
        )
    }
