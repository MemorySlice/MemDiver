.PHONY: test test-slow test-corpus validate cov lint typecheck fmt security fe-install fe-test fe-typecheck fe-lint fe-check check

# ---------------------------------------------------------------------------
# Corpus environment variables (read by tests/_paths.py + tests/fixtures/
# tls_ground_truth.py). Both are OPTIONAL: with neither set, the resolver ends
# at ~/Desktop/tls_dumps, and if that is absent every corpus-backed test skips
# cleanly. Nothing here ever fails for want of a corpus.
#
#   MEMDIVER_DATASET_ROOT   dataset root for the `requires_dataset` gate
#                           (also settable per-run as `--dataset-root=PATH`,
#                           or persistently as config.json["dataset_root"]).
#   MEMDIVER_TLS_DUMPS_DIR  root of the TLS-dump corpus that the corpus test
#                           BODIES read. It is the last step of the
#                           MEMDIVER_DATASET_ROOT resolution chain, so setting
#                           just this one is enough to light up both.
#
# Point them at the same tree unless you deliberately want them to differ.
CORPUS ?= $(HOME)/Desktop/tls_dumps

test:
	python -m pytest -q --ignore-glob='tests/e2e_*_test.py'

# The `slow` marker is deselected by the default addopts (pyproject.toml), so
# the auto-floor cost ratchets in tests/test_benchmarks.py need an explicit
# runner. CI runs this as a step in the `test` job; run it locally before
# touching engine/auto_floor.py or engine/brute_force.py.
test-slow:
	python -m pytest -q -m slow

# Every corpus-backed test, bounded slices AND the full-corpus passes, against
# a real corpus. Override the tree with `make test-corpus CORPUS=/path/to/tree`.
#
# `-m requires_dataset` REPLACES the default addopts selector (last `-m` wins),
# so the one `slow`-marked full-corpus pass is included here and only here.
#
# On marking: only the FULL-corpus passes carry `slow`. The bounded slices stay
# unmarked on purpose -- `slow` would evict them from `make test`, which is the
# only command a developer who HAS the corpus ever runs, and it would buy
# nothing in CI.
#
# THIS TARGET DOES NOT RUN IN CI, AND CI DOES NOT COVER THESE TESTS. No GitHub
# runner has the ~170 GB corpus, so there they skip -- exactly as the corpus-
# backed `slow` tests already do in the "Run the slow ratchets" step
# (.github/workflows/ci.yml). Marking these tests differently cannot change
# that: the gap is the missing corpus, not the marker. Real-corpus coverage is
# a local, developer-run gate only.
test-corpus:
	MEMDIVER_DATASET_ROOT="$(CORPUS)" MEMDIVER_TLS_DUMPS_DIR="$(CORPUS)" \
		python -m pytest -q -m requires_dataset -v

# The Volatility 3 plugin claim gate (tests/test_vol3plugins_corpus_gate.py): one test per
# claim ID, a claim table (claim, vol version, result, seconds) at the end. The in-repo sample
# claims (samples/) need nothing; the rest skip cleanly unless pointed at their inputs:
#
#   MEMDIVER_VOL3_VOL         stock `vol` (or a vol.py); default: the vol beside `python`
#   MEMDIVER_VOL3_ALT_VOL_PY  a second volatility3 tree's vol.py (e.g. 2.28.2): every claim reruns
#   MEMDIVER_VOL3_BARE_VOL    a `vol` with neither MemDiver nor a crypto library (claim C-SYN2)
#   MEMDIVER_SECRETS_CORPUS   absolute dir of the x86_64 acquired-secrets captures (DM/WG/KR/FS/EC/LA57)
#
# Fetch the public capture corpus first (scripts/fetch_contest_corpus.py: download or local
# mirror, SHA256SUMS verified, .xz decompressed) and run the gate against it:
#
#   make validate CORPUS_FETCH=1 CORPUS_RECORD=<zenodo id|URL|DOI> [CORPUS_DIR=/path]
#   make validate CORPUS_FETCH=1 CORPUS_MIRROR=/local/copy/of/record [CORPUS_DIR=/path]
#
# VALIDATE_ARGS is passed to pytest (e.g. VALIDATE_ARGS='-k "C_DM1 or C_LA57"').
CORPUS_DIR ?= $(HOME)/.cache/memdiver/contest_corpus
VALIDATE_ARGS ?=
validate:
ifeq ($(CORPUS_FETCH),1)
	python scripts/fetch_contest_corpus.py --target "$(CORPUS_DIR)" \
		$(if $(CORPUS_MIRROR),--mirror "$(CORPUS_MIRROR)",--record "$(CORPUS_RECORD)")
	MEMDIVER_SECRETS_CORPUS="$(CORPUS_DIR)" \
		python -m pytest -q -p no:cacheprovider -rs tests/test_vol3plugins_corpus_gate.py $(VALIDATE_ARGS)
else
	python -m pytest -q -p no:cacheprovider -rs tests/test_vol3plugins_corpus_gate.py $(VALIDATE_ARGS)
endif

cov:
	python -m pytest -q --ignore-glob='tests/e2e_*_test.py' --cov --cov-report=term-missing --cov-fail-under=82

lint:
	ruff check .

typecheck:
	mypy

fmt:
	ruff format .

security:
	bandit -c pyproject.toml -r . -x run.py -b .bandit-baseline.json
	pip-audit

# ONE hoisted install at the repo root. frontend/ and tests/e2e/ are npm
# workspaces: there is no per-package lockfile and no per-package node_modules.
# Never run `npm ci` inside a workspace -- see CONTRIBUTING.md.
fe-install:
	npm ci

# All three now run from the repo root: the lockfile, the hoisted bins and the
# ESLint config all live there. `tsc -b frontend` walks the same three project
# references (app, node, test) that `cd frontend && npx tsc -b` used to.
fe-test:
	npm run test:run

fe-typecheck:
	npx tsc -b frontend

fe-lint:
	npm run lint

fe-check: fe-typecheck fe-test

check: lint typecheck test
