# Adding a dump source

A *dump source* is how MemDiver opens a memory dump (or container) and reads
byte ranges out of it. `open_dump(path, ...)` picks a source by consulting an
ordered **detector registry** — so a new source type slots in without editing
`open_dump` itself.

## 1. Satisfy the `DumpSource` protocol

`DumpSource` (`core/dump_source.py`) is a `runtime_checkable` `typing.Protocol`.
Any object that structurally provides its members qualifies — no base class to
inherit. The contract:

- Properties: `path`, `name`, `format_name`, `size`
- Methods: `size_for(...)`, `open()`, `close()`, `__enter__`/`__exit__`,
  `read_range(offset, length)`, `find_all(needle)`, `iter_ranges()`,
  `metadata()`

`read_all()` is intentionally **not** part of the structural contract — sources
backing multi-GB views (e.g. gcore, region-mapped raw) omit it on purpose.
Feature-test it with `hasattr(source, "read_all")` rather than assuming it.

```python
class MyDumpSource:
    def __init__(self, path, **_):   # accept **_ so key-material kwargs are safe
        self.path = path
        self.format_name = "myfmt"
    # ... implement the members above ...
```

## 2. Register a detector + factory

```python
from memdiver.core.dump_source import register_dump_source

def _detect_myfmt(path, header_bytes) -> bool:
    # header_bytes is the first 18 bytes (empty on read error)
    return header_bytes.startswith(b"MYFMT")

register_dump_source(_detect_myfmt, MyDumpSource, priority=50)
```

`open_dump` iterates registered entries in **descending priority** (stable
insertion-order tie-break). Built-ins occupy fixed tiers — MSL=100, ELF-core=90,
gdb-suffix=80, lldb-suffix=70, and an always-matching raw fallback at the lowest
priority — so a default-priority (`0`) source is tried after the specific
built-ins but ahead of the raw fallback. Pick a priority that reflects how
specific your detector is.

The factory is called as `factory(path, key=..., passphrase=...,
kem_private_key=...)`; accept and ignore the key-material kwargs (`**_`) if your
format is unencrypted.

## 3. (Optional) out-of-tree via entry point

The steps above register in-tree. An installed third-party package can add a
dump source without living in this repo by advertising it under the
`memdiver.dump_sources` entry-point group. MemDiver loads the group exactly once,
right after the built-in sources are registered.

The entry point may resolve to either a **module** (imported for its
module-level `register_dump_source(...)` side effect) or a **callable** (invoked
with no arguments to self-register):

```toml
# pyproject.toml of your out-of-tree package
[project.entry-points."memdiver.dump_sources"]
# a module whose import calls register_dump_source(...)
myfmt = "my_pkg.memdiver_source"
# ...or a callable that self-registers when invoked
# myfmt = "my_pkg.memdiver_source:register"
```

Discovery is additive and failure-isolated — if your package is not installed it
is a silent no-op, and a broken entry point is logged and skipped without
affecting the built-ins.

## 4. Test

Add a test under `tests/` (see `tests/test_dump_source_registry.py`): register
your source, write a tiny synthetic file matching your detector, and assert
`open_dump(path)` returns your source — and that registering it does not perturb
the built-in precedence.
