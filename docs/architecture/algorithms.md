# algorithms/

Plugin registry. Drop a `.py` file in `algorithms/known_key/` or `algorithms/unknown_key/`; a subclass of `BaseAlgorithm` with a non-empty `name` is discovered automatically via `pkgutil.walk_packages`.

## Interface

```python
class BaseAlgorithm:
    name: str         # registry key (must be truthy)
    description: str
    mode: str         # "known_key" or "unknown_key"

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        ...
```

- `AnalysisContext` carries `library`, `protocol_version`, `phase`, `secrets` (ground truth if any), and `extra` (arbitrary params).
- `AlgorithmResult` carries `algorithm_name`, `confidence`, `matches`, `metadata`.
- `Match` carries `offset`, `length`, `confidence`, `label`, `data`, `metadata`.

## Discovery

`algorithms.registry.get_registry()` is a module-level singleton. First call walks three subdirs (`known_key/`, `unknown_key/`, `patterns/`) and registers every subclass of `BaseAlgorithm` with a truthy `name`.

Adding an algorithm is one file. See [](../contributing/adding_algorithms.md).
