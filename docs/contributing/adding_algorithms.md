# Adding an algorithm

MemDiver auto-discovers algorithms via `pkgutil.walk_packages` on import. Adding one is a single file.

## 1. Choose a mode

- `known_key` → requires `context.secrets` (ground-truth keylog). Place in `algorithms/known_key/`.
- `unknown_key` → no ground truth. Place in `algorithms/unknown_key/`.

## 2. Subclass `BaseAlgorithm`

```python
# algorithms/unknown_key/my_algo.py
from algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from core.constants import UNKNOWN_KEY


class MyAlgoAlgorithm(BaseAlgorithm):
    name = "my_algo"
    description = "One-line summary shown in the UI algorithm picker."
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        threshold = context.extra.get("my_threshold", 0.5)
        matches: list[Match] = []
        # ... analyze dump_data, append Match instances ...
        confidence = 1.0 if matches else 0.0
        return AlgorithmResult(
            algorithm_name=self.name,
            confidence=confidence,
            matches=matches,
            metadata={"threshold": threshold},
        )
```

No registration call is needed — the next `get_registry()` call discovers the class via `pkgutil.walk_packages` + `issubclass(BaseAlgorithm)`.

## 3. Surface in the UI

Add `"my_algo"` to `frontend/src/stores/app-store.ts` `ANALYSIS_ALGORITHMS`. Optionally extend `frontend/src/utils/algorithm-availability.ts` if the algorithm has mode-specific requirements.

## 4. Test

Write a unit test under `tests/test_my_algo.py` following the pattern of existing `tests/test_*.py`. Include a fixture dump from `tests/fixtures/generate_*.py` so the test is self-contained.
