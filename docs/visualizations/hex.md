# Hex viewer

:::{admonition} Available in
:class: tip
**SPA** (main panel) · **Marimo** sandbox
:::

Color-coded hex / ASCII dump viewer. Virtualized rows via `@tanstack/react-virtual`; paged reads through the `/api/inspect/hex-raw` endpoint.

## Color classifications

| Class | Meaning |
|---|---|
| `INVARIANT` | identical across all runs (structural constants, `.rodata`) |
| `STRUCTURAL` | low variance; typically pointers that survive ASLR |
| `POINTER` | mid variance; ASLR-shifted pointers |
| `KEY_CANDIDATE` | high variance; possible cryptographic material |

## Overlays

- **Structure overlay** — colored fields from the structure library (TLS `SSL_SESSION`, SSH `session_id` layouts, …).
- **Neighborhood overlay** — variance slice around a selected byte offset.

```{figure} /_static/screenshots/05_hex_with_overlay.png
:alt: Hex viewer in dark theme with a TLS structure overlay coloring bytes by field role
:align: center

Hex viewer with structure overlay applied.
```

## Byte search

The toolbar's search box (placeholder *search pattern*, button **Find**, or press `Enter`) looks for every occurrence of a byte sequence in the open dump. A **Pattern format** selector next to it decides how the typed text is turned into bytes:

| Selector label | Format id | What you type | Bytes searched |
|---|---|---|---|
| **Auto** (default) | `auto` | anything | `hex` if the input is whole-byte hex, otherwise `text` |
| **Hex** | `hex` | `deadbeef`, `de ad be ef`, `0xDEADBEEF` | whitespace and one leading `0x`/`0X` are stripped; an even number of hex digits is required |
| **Text** | `text` | `-----BEGIN` | UTF-8 encoding of the input |
| **Text (UTF-16LE)** | `utf16le` | `password` | UTF-16LE code units, no BOM |
| **Base64** | `base64` | `3q2+7w==` | decoded base64 (whitespace ignored, length must be a multiple of 4) |
| **u32 LE** / **u32 BE** | `u32le` / `u32be` | `4096`, `0x1000` | the unsigned integer as 4 bytes, little / big endian |
| **u64 LE** / **u64 BE** | `u64le` / `u64be` | `0x7ffd12345678` | the unsigned integer as 8 bytes, little / big endian |

Integer inputs accept decimal or `0x` / `0o` / `0b` prefixes (Python `int(x, 0)` spelling); negative values and values that do not fit the width are rejected.

`Auto` never guesses base64 or an integer — those character sets overlap ordinary text — so it only ever chooses between hex and text. Words like `dead` or `cafe` are valid hex *and* valid text, so instead of guessing silently the box shows a live preview of the resolved bytes (`Hex · 4 B  de ad be ef`) before you search, plus an **also valid as …** / **try …** hint that switches the reading in one click (base64 is offered only for inputs of at least 16 characters). Needles shorter than 4 bytes show **⚠ short — many matches**. The UI requests at most 500 hits; a capped result shows as `500+ hits`. **Clear search** removes the highlights.

The same parser (`core/needle.py`, mirrored in `frontend/src/utils/needle.ts` and pinned together by `tests/fixtures/needle_vectors.json`) backs `GET /api/inspect/byte-search?pattern_format=…`, so the CLI and MCP surfaces accept the same format ids — there `auto` is resolved server-side.

## Consensus overlay

With two or more dumps selected, the **Main view layout** switcher above the hex panel offers **Single**, **Side by side (N)** (every selected dump in its own aligned pane) and **Overlay** (every selected dump superimposed byte by byte, coloured by the consensus vector). See [Consensus view](consensus.md#hex-overlay) for the overlay's controls, the byte inspector and the region browser.

On a single `.msl` dump with the consensus overlay enabled, the viewer switches itself to the **VA** view mode, because the per-byte classes live in virtual-address coordinates.
