# Real capture samples

## `chrome_min.msl` — known-modified header (PrevHash chain breaks at block 0)

A real memslicer capture of Chrome (pid 20216). It is **not** regenerable and
is kept byte-for-byte as committed.

The file header was hand-edited after capture: commit `f147d8c` changed the
single byte at offset `0x0B` (high byte of the u16 Version field at `0x0A`)
from `0x00` to `0x01`, i.e. Version `0.1` -> `1.1`, so the then-new spec §3.4
major-version check in `MslReader` would accept the draft-era file.

Consequences for `msl.integrity.verify_chain` (spec §4.4):

- Block 0's PrevHash (`8a144f64…`) is the BLAKE3 of the **original** header;
  the current header hashes to `379c5860…`, so verification fails at block 0
  (offset `0x40`).
- All 368 block-to-block links after block 0 are intact.
- Restoring `0x0B` to `0x00` reproduces block 0's PrevHash exactly, but the
  restored file is Version 0.1, which the reader rejects as an unsupported
  major version — so the patched header is kept.

`tests/test_fixture_chain_integrity.py` allowlists this file and asserts both
facts (failure exactly at block 0, and that the original byte reconstructs the
recorded PrevHash), so any further modification is still detected.
