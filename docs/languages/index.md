# Languages

The MemDiver documentation is currently **English-only** (V1). The Sphinx build is already prepared for translation:

- `language = "en"` is set in `docs/conf.py`.
- `locale_dirs = ["locales/"]` points at an empty directory ready for `.po` files.
- `gettext_compact = False` so each source document gets its own message catalog.

## Contributing a translation

```bash
pip install -e ".[docs]" sphinx-intl
sphinx-build -b gettext docs docs/_build/gettext
sphinx-intl update -p docs/_build/gettext -l de -l fr -l ja
# edit docs/locales/<lang>/LC_MESSAGES/*.po
sphinx-build -b html -D language=<lang> docs docs/_build/html.<lang>
```

Translations are not yet part of the CI build. When the first `.po` files land we will wire a matrix-of-languages job into `.github/workflows/docs.yml`.
