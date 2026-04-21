# Algorithms

MemDiver ships **8 detection algorithms**, discovered automatically by `algorithms.registry`. One requires ground-truth secrets (`known_key`); seven do not (`unknown_key`).

| Algorithm | Mode | Purpose |
|---|---|---|
| [`exact_match`](exact_match) | `known_key` | Literal byte-search for known-secret sequences using `context.secrets`. |
| [`entropy_scan`](entropy_scan) | `unknown_key` | Sliding-window Shannon entropy above a threshold. |
| [`change_point`](change_point) | `unknown_key` | CUSUM-based entropy-plateau detection. |
| [`differential`](differential) | `unknown_key` | DPA-inspired cross-run byte variance. |
| [`constraint_validator`](constraint_validator) | `unknown_key` | TLS KDF relationship verification for candidates. |
| [`user_regex`](user_regex) | `unknown_key` | Custom regex patterns. |
| [`pattern_match`](pattern_match) | `unknown_key` | Structural matching from JSON pattern definitions. |
| [`structure_scan`](structure_scan) | `unknown_key` | Structure-library-backed overlay + best-match scoring. |

## Contracts

All algorithms share the same interface from `algorithms.base`:

```python
class BaseAlgorithm:
    name: str
    description: str
    mode: str

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult: ...
```

See [](../architecture/algorithms.md) for the registry internals and [](../contributing/adding_algorithms.md) for adding a new one.

```{toctree}
:hidden:

exact_match
entropy_scan
change_point
differential
constraint_validator
user_regex
pattern_match
structure_scan
```
