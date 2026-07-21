# Adding a KDF

MemDiver auto-discovers KDF (Key Derivation Function) plugins the same way it
discovers algorithms. In-tree KDFs are single files under `core/`; out-of-tree
KDFs can be shipped by any installed package via an entry point.

## 1. Subclass `BaseKDF`

Create `core/kdf_<name>.py`. The registry globs `core/kdf_*.py`, so the
`kdf_` filename prefix is required for in-tree discovery.

```python
# core/kdf_myproto.py
from typing import List, Optional

from memdiver.core.kdf_base import BaseKDF, KDFParams
from memdiver.core.models import CryptoSecret


class MyProtoKDF(BaseKDF):
    name = "myproto_kdf"          # unique key in the registry
    protocol = "MYPROTO"          # matched by get_for_protocol()
    versions = {"1"}              # matched by get_for_protocol()

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        ...

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        ...

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
        hash_candidates: Optional[List[bytes]] = None,
    ) -> float:
        ...
```

No registration call is needed — the next `get_kdf_registry()` call discovers
the class via the shared plugin loader (`core/plugin_discovery.py`) and
`issubclass(BaseKDF)`. A KDF whose `__init__` raises is logged and skipped; it
no longer aborts discovery of the other KDFs.

## 2. (Optional) Ship a KDF from an out-of-tree package

Installed packages can advertise KDFs under the `memdiver.kdfs` entry-point
group without living in `core/`. The entry point may point at a `BaseKDF`
subclass directly, or at a module that will be scanned for subclasses.

```toml
# pyproject.toml of the external package
[project.entry-points."memdiver.kdfs"]
myproto = "my_package.kdf:MyProtoKDF"
```

Discovery degrades silently when no such packages are installed. The algorithm
equivalent is the `memdiver.algorithms` entry-point group (see
[Adding an algorithm](adding_algorithms.md)).

## 3. Test

Write a unit test under `tests/test_*.py` following existing KDF tests. Assert
your KDF appears in `get_kdf_registry().list_all()` and that
`get_for_protocol("MYPROTO", "1")` returns it.
