# docs/screenshots/

Playwright-driven regeneration of the 11 baseline screenshots embedded in the Sphinx site.

## Contents

| File | Purpose |
|---|---|
| `capture.py` | Playwright driver — starts the FastAPI+React stack, seeds a dataset, captures 11 PNGs to `docs/_static/screenshots/`. |
| `seed_data.py` | Deterministic fixture generator wrapping the six `tests/fixtures/generate_*.py` scripts. |
| `captions.json` | Per-slug alt text, viewport, theme, mode, tolerance. The source of truth for which screenshots exist and what they contain. |
| `generate_placeholders.py` | Generates plain placeholder PNGs so the Sphinx build succeeds on a fresh clone with no running stack. Run once; replaced by real captures when `capture.py --update` is run. |

## Regenerating baselines

```bash
# One-time setup
pip install -e ".[docs]" playwright
python -m playwright install --with-deps chromium

# All 11
python docs/screenshots/capture.py --update

# Just one
python docs/screenshots/capture.py --one 04_workspace_default

# Verify deterministic seed
python docs/screenshots/capture.py --verify-seed
```

The driver starts `memdiver web --port 8088` in the background, waits for `/docs` to return 200, seeds `$MEMDIVER_DATASET_ROOT` into a tempdir, and tears the backend down in a `finally:` block.

## Adding a new screenshot

1. Add a capture function to `capture.py`'s `CAPTURE_REGISTRY`. Follow the existing pattern: `_goto_and_wait(page)` → wait for `data-testid` → optional UI interactions → return.
2. Append an entry to `captions.json` under `shots[]`: `slug`, `title`, `alt`, `theme`, `mode`, `viewport`, `tolerance`.
3. Reference the image from a Sphinx page via:
   ````markdown
   ```{figure} /_static/screenshots/<slug>.png
   :alt: <description>
   :align: center
   ```
   ````
4. Run `python docs/screenshots/capture.py --one <slug>` to regenerate just that one. Commit the PNG.

## Flake prevention

`capture.py` already injects ten flake-reduction techniques: fixed `Date.now`, seeded `Math.random`, disable-animations CSS, scrollbar suppression, `--force-color-profile=srgb`, `--font-render-hinting=none`, `reduced_motion="reduce"`, `device_scale_factor=2`, hidden caret, pre-seeded localStorage.

When adding UI components that will be captured, expose a `data-testid="<slug>"` attribute and toggle `data-loaded="true"` once async data arrives — capture.py can then wait on a stable selector rather than `sleep()`.

## Anonymity

Screenshots must not capture terminals, IDE panels, or any chrome that reveals a username, hostname, home-directory path, or institutional affiliation. The driver runs headless against a temp dataset, so the rendered SPA is the only content. Spot-check new captures with:

```bash
grep -RIL --include="captions.json" . || true
```
