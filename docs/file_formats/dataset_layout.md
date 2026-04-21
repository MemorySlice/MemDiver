# Dataset layout

MemDiver expects memory dumps organized by protocol version, scenario, library, and run.

```
<dataset_root>/
  TLS{12,13}/
    {scenario}/
      {library}/
        {library}_run_{12,13}_{N}/
          {TIMESTAMP}_(pre|post)_{phase}.dump    # or .msl
          keylog.csv                              # TLS ground-truth secrets
          timing_*.csv                            # optional timing data
          *.json / *.meta                         # optional sidecars
```

Protocol versions recognized today: `TLS12`, `TLS13`, `SSH2`. Scenarios and libraries are free-form; MemDiver auto-discovers them by name.

Configure the root via `config.json` (`dataset_root` key), `MEMDIVER_DATASET_ROOT` env var, or the UI file browser. Command-line overrides: `--root` on `memdiver scan`, positional `library_dirs` on `memdiver analyze`.

## Filename regexes

- Dump: `^(\d{8}_\d{6}_\d+)_(pre|post)_(.+)\.(dump|msl)$`
- Run directory: `^(.+?)_run_(\d+)_(\d+)$`

## Phase normalization

Different libraries name lifecycle phases differently (e.g. `handshake_complete` vs `post_handshake` vs `after_handshake`). `core.phase_normalizer.PhaseNormalizer` canonicalizes these for cross-library comparison.
