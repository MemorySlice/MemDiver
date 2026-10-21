# Visualization views

MemDiver ships nine visualization views. Four are actively rendered in both the React SPA and the Marimo notebook; the cross-run variance map is rendered in the SPA only, and the heatmap in Marimo only. The remaining three have component files under `frontend/src/components/charts/` and `ui/views/` but are not currently wired into either the SPA's default layout or `run.py`'s rendered cells — they remain accessible by extending the notebook or importing the component directly. Each page below marks its availability explicitly.

| View | SPA | Marimo |
|---|:---:|:---:|
| [Hex viewer](hex.md) | ✅ | ✅ |
| [Entropy profile](entropy.md) | ✅ | ✅ |
| [Consensus view](consensus.md) | ✅ | ✅ |
| [Pattern Architect](architect.md) | ✅ | ✅ |
| [Key-presence heatmap](heatmap.md) | — | ✅ |
| [Cross-run variance map](variance_map.md) | ✅ | component exists, not wired in `run.py` |
| [Phase lifecycle](phase_lifecycle.md) | — | component exists, not wired in `run.py` |
| [Cross-library comparison](cross_library.md) | — | component exists, not wired in `run.py` |
| [Differential diff](differential_diff.md) | — | component exists, not wired in `run.py` |

```{toctree}
:hidden:

hex
entropy
consensus
architect
heatmap
variance_map
phase_lifecycle
cross_library
differential_diff
```
