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

## 3. (Optional) Ship an algorithm from an out-of-tree package

Installed packages can advertise algorithms under the `memdiver.algorithms`
entry-point group without living in `algorithms/`. The entry point may point at
a `BaseAlgorithm` subclass directly, or at a module that will be scanned for
subclasses.

```toml
# pyproject.toml of the external package
[project.entry-points."memdiver.algorithms"]
my_algo = "my_package.algo:MyAlgoAlgorithm"
```

Discovery degrades silently when no such packages are installed. The KDF
equivalent is the `memdiver.kdfs` entry-point group (see
[Adding a KDF](adding_kdf.md)).

## 4. Surface in the UI

Add `"my_algo"` to `frontend/src/stores/app-store.ts` `ANALYSIS_ALGORITHMS`. Optionally extend `frontend/src/utils/algorithm-availability.ts` if the algorithm has mode-specific requirements.

## 5. Test

Write a unit test under `tests/test_my_algo.py` following the pattern of existing `tests/test_*.py`. Include a fixture dump from `tests/fixtures/generate_*.py` so the test is self-contained.
