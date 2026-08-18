.PHONY: test cov lint typecheck fmt security fe-test fe-typecheck fe-lint check

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

fe-test:
	cd frontend && npm run test:run

fe-typecheck:
	cd frontend && npx tsc -b

fe-lint:
	cd frontend && npm run lint

check: lint typecheck test
