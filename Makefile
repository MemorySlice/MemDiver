.PHONY: test cov lint typecheck fmt security fe-install fe-test fe-typecheck fe-lint fe-check check

test:
	python -m pytest -q --ignore-glob='tests/e2e_*_test.py'

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
