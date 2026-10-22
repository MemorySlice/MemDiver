# Experiment quickstart

The experiment harness spawns a target process, lets it reach a known state, and triggers memory capture from each available backend.

## Backends

| Backend | Output | Install |
|---|---|---|
| `memslicer` | `.msl` | ships in the default `pip install memdiver` |
| `lldb` | `.dump` | OS package (see below) |
| `fridump` | `.dump` | the `fridump` module/script itself must be installed separately (`frida` ships in the default install); needs an attachable target |

### LLDB install per OS

```bash
# macOS  (LLDB ships with Xcode Command Line Tools)
xcode-select --install

# Debian / Ubuntu
sudo apt install lldb

# Fedora / RHEL
sudo dnf install lldb
```

:::{note}
`fridump` is a Frida-based bulk memory dumper. It is **not** the same as friTap, despite the name similarity.
:::

## First experiment

1. `pip install memdiver` — `frida-tools` + `memslicer` are part of the default install. Optionally `brew install --cask` Xcode CLT or `apt install lldb` for the LLDB backend.
2. Write a target script that prints `MEMDIVER_PID=<pid>`, `MEMDIVER_KEY=<hex>`, `MEMDIVER_IV=<hex>`, `MEMDIVER_READY=1` on stdout, then idles with the key in memory.
3. Run:

   ```bash
   memdiver experiment --target path/to/target.py --num-runs 10 --output-dir ./experiment_output
   ```

4. Inspect `./experiment_output/AES256/aes_key_in_memory/<tool>/` for dumps + `keylog.csv`, and `./experiment_output/plugins/*.py` for the auto-generated Volatility3 plugin.

## Capturing a running process (local, Android, remote)

`experiment` starts its own local target. To dump a process that is already running, possibly on an Android device or behind a remote frida-server, use `capture`:

```bash
memdiver capture 5552 app.msl --device usb:emulator-5556           # memslicer -D
memdiver capture 5552 app.msl --device usb                         # first USB device (-U)
memdiver capture 1234 app.msl --device remote:192.168.1.20:27042   # remote frida-server (-R)
memdiver capture 4242 snap.lldb_raw.bin --tool lldb                # local, chunked lldb
```

Every region that was not captured is reported (stderr, the JSON report's `skipped` list, and `<dump>.capture.json`). See the `capture` notes in the [CLI reference](../user_guide/cli_reference.md).

## Layout produced

```
experiment_output/
  AES256/aes_key_in_memory/<tool>/<tool>_run_256_<N>/
    <TIMESTAMP>_pre_snapshot.<msl|dump>
    keylog.csv
  plugins/<tool>_aes256_key.py     # Volatility3 plugin
  plugins/<tool>_aes256_key.yar    # YARA rule
```
