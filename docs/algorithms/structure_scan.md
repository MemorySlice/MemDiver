# structure_scan

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/structure_scan.py`

Structural overlay scanner. The built-in key structures only require their bytes to be non-zero, so almost any offset of random data "matches" them; what identifies a key is the **shape** of the high-entropy region around it. The scan therefore:

1. **Finds exact high-entropy regions** — the step-1 entropy overview (`core.entropy_overview.stream_entropy_overview`) at `_SCAN_WINDOW = 32` and the window-aware default threshold (`core.entropy.default_entropy_threshold(32)` = 4.5), with the Entropy tab's region rules (`region_min_span` / `region_join_gap`). The dump (bytes or mmap) is streamed in 1 MiB views and never copied.
2. **Keeps key-sized regions.** A region is a candidate for structure size `S` (`total_size`, or each `size_choices` total) only if its covered span lies in `[S − 8, S + 62]`. Above: every window of the region overlaps the structure, so each side extends at most `W − 1 = 31` bytes; in heap-like data the measured excess is 1–38 bytes (shape fit 1.0 up to `S + 38`, falling to 0.5 at the bounds). Below: an edge window of the key may miss the threshold (`W / 4`).
3. **Probes a few offsets per region**: 8-aligned, then 4-aligned, then any start, largest size first. A window passes when its bytes look uniformly random (collision count within the 99.9 % Poisson bound, and neither 8-byte edge block is zeros/padding, a pointer's `00 00` high bytes or printable text). One `best_match_structure` call on just those bytes, against the structures of that size, names the match.
4. **Skips bulk.** Regions longer than the largest structure + 62 bytes (encrypted pages, compressed data) are counted in `skipped_bulk_regions` / `skipped_bulk_bytes` and not scanned.
5. **Finds magic-bearing structures** (any field with an exact `equals` value, e.g. `elf64_header`) by a `find` of the magic over the whole buffer, independent of entropy.

Confidence = shape fit (span vs size × randomness of the window) × the constraint score. At most `MAX_MATCHES = 4096` matches (1024 per magic structure); `truncated: true` in the metadata says the cap was hit. A protocol filter (`protocol_version` TLS / SSH) restricts the structures as before.

Limits: keys shorter than about 26 bytes rarely lift a 32-byte window to 4.5 bits/byte and are mostly not seen; contiguous runs of several secrets longer than 134 bytes count as bulk.

## When to use

- Libraries with richly structured key material (TLS 1.3 traffic secrets inside `SSL_SESSION`, SSH `KEX` state).
- When you already have a Kaitai-Struct or structure-definition JSON for the target and want to annotate the hex viewer.

## Output

`Match.label = "struct:<structure_name>"`. Feeds the "Structure overlay" detail-panel view in the React SPA. Region matches carry `size_class`, `region_offset`, `region_span`, `shape_fit`, `constraint_score` and `candidate_structures` (every structure of that size, since a random 48-byte block fits a TLS 1.2 master secret as well as a SHA-384 TLS 1.3 secret). Result metadata: `high_entropy_regions`, `candidate_regions`, `skipped_bulk_regions`, `skipped_bulk_bytes`, `magic_matches`, `matches_found`, `truncated`.

## Note

The README's original "7 algorithms" count omitted this one. It is a first-class, default-enabled algorithm.
