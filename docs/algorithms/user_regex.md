# user_regex

**Mode:** `unknown_key` &nbsp;·&nbsp; **File:** `algorithms/unknown_key/user_regex.py`

Regex sweep over the dump. Each pattern becomes one or more `Match` instances labeled with the pattern's `name`.

## Parameters (read from `context.extra`)

| Key | Shape |
|---|---|
| `user_patterns` | `[{"name": "<label>", "regex": "<python-re>"}]` |

## When to use

- Finding printable markers (library banners, server certificates as strings).
- Quick checks for magic bytes / framing before reaching for a structured algorithm.
- Ad-hoc triage in Marimo / the web UI.
