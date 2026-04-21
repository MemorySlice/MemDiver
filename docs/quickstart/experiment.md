# Experiment quickstart

The experiment harness spawns a target process, lets it reach a known state, and triggers memory capture from each available backend.

## Backends

| Backend | Output | Install |
|---|---|---|
| `memslicer` | `.msl` | `pip install memdiver[experiment]` (ships `memslicer` binary) |
| `lldb` | `.dump` | OS package — Xcode CLT on macOS, `apt install lldb` on Debian/Ubuntu |
| `fridump` | `.dump` | `pip install memdiver[experiment]` (pulls `frida-tools`) |

:::{note}
`fridump` is a Frida-based bulk memory dumper. It is **not** the same as friTap, despite the name similarity.
:::

## First experiment

1. `pip install "memdiver[experiment]"` — installs `frida-tools` + `memslicer`. Optionally `brew install --cask` Xcode CLT or `apt install lldb` for the LLDB backend.
2. Write a target script that prints `MEMDIVER_PID=<pid>`, `MEMDIVER_KEY=<hex>`, `MEMDIVER_IV=<hex>`, `MEMDIVER_READY=1` on stdout, then idles with the key in memory.
3. Run:

   ```bash
   memdiver experiment --target path/to/target.py --num-runs 10 --output-dir ./experiment_output
   ```

4. Inspect `./experiment_output/AES256/aes_key_in_memory/<tool>/` for dumps + `keylog.csv`, and `./experiment_output/plugins/*.py` for the auto-generated Volatility3 plugin.

## Layout produced

```
experiment_output/
  AES256/aes_key_in_memory/<tool>/<tool>_run_256_<N>/
    <TIMESTAMP>_pre_snapshot.<msl|dump>
    keylog.csv
  plugins/<tool>_aes256_key.py     # Volatility3 plugin
  plugins/<tool>_aes256_key.yar    # YARA rule
```
