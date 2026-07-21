# Adding a binary format

MemDiver describes every binary format with a single `FormatDescriptor` in
`core/binary_formats/format_descriptor.py`.  Today detection, the Kaitai parser
map and the navigation-tree dispatch table all read from this one registry, so
adding a format for those three concerns is a single registration instead of
editing three parallel tables.

Structure definitions are not yet wired through the registry: although
`FormatDescriptor.structure_defs` exists and is populated, nothing consumes it
yet — `core/structure_library.py` still imports `ELF_DEFS` / `PE_DEFS` /
`MACHO_DEFS` directly.  Routing structure-defs through the registry is a tracked
follow-up, so for now register a new format's structure definitions via the
existing `core/structure_library.py` path in addition to your descriptor.

## 1. Build a descriptor

```python
from memdiver.core.binary_formats.format_descriptor import (
    FormatDescriptor,
    register_format,
)

register_format(FormatDescriptor(
    name="myfmt",
    aliases=("myfmt32", "myfmt64"),          # share one Kaitai parser
    magics=(("myfmt", 0, b"\x89MYF"),),      # (result_name, offset, bytes)
    kaitai=("memdiver.core.binary_formats.kaitai_compiled.myfmt", "MyFmt"),
    structure_defs=None,                     # or a list of StructureDef
))
```

Fields (all optional except `name`):

- `name` / `aliases` — the canonical name plus every alias that resolves to the
  same descriptor and Kaitai parser.
- `magics` — fixed offset-0 (or offset-N) signatures, checked in order.
- `classifier` — optional refinement of a matched name (e.g. ELF's class byte
  chooses `elf64` vs `elf32`).
- `detector` — optional custom routine for formats whose detection needs more
  than a fixed compare (e.g. PE's `MZ` + `PE\0\0`). Return a name or `None`.
- `kaitai` — `(module_path, class_name)` of the compiled Kaitai parser.
- `nav_builders` — `{name: builder(data) -> NavNode}` for the header navigator.
- `structure_defs` — list of `StructureDef` header-layout objects.

## 2. Detection precedence

`FormatRegistry.detect()` checks all `magics` first (in registration order),
then all `detector`s.  Register detection-only formats (no parser) with just
`magics` — they still surface through `detect_format` and `MAGIC_SIGNATURES`.

## 3. Navigation-tree builders

Builder functions typically live in `core/binary_formats/navigator.py` next to
the other `_build_*_tree` helpers.  Attach them to your descriptor there (see
`_register_builtin_nav_builders`) so `build_nav_tree` picks them up.  A format
without a builder simply returns no tree.

## 4. (Optional) out-of-tree via entry point

The registration above lives in-tree. An installed third-party package can add a
format without living in this repo by advertising it under the `memdiver.formats`
entry-point group. MemDiver loads the group exactly once, when the default
`FormatRegistry` is first built (its lazy `get_default_registry()` init).

The entry point may resolve to either a **module** (imported for its
module-level `register_format(...)` side effect) or a **callable** (invoked with
no arguments to self-register):

```toml
# pyproject.toml of your out-of-tree package
[project.entry-points."memdiver.formats"]
# a module whose import calls register_format(...)
myfmt = "my_pkg.memdiver_format"
# ...or a callable that self-registers when invoked
# myfmt = "my_pkg.memdiver_format:register"
```

Discovery is additive and failure-isolated — a silent no-op when your package is
not installed, and a broken entry point is logged and skipped.

## 5. Test

Add coverage under `tests/test_format_registry.py` (or a dedicated file):
register a dummy descriptor and assert it is detectable via `detect()` and
retrievable via `get()`, and that the three consumers — the Kaitai lookup, the
navigator builders and `format_detect` — agree with the registry.
