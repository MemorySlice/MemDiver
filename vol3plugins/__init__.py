"""MemDiver's Volatility 3 plugin directory.

This directory is two things at once:

* the directory passed to stock Volatility 3 with ``vol -p <this dir>`` (print it with
  ``memdiver vol3 plugin-dir``, planned), where its files load as ``volatility3.plugins.*``; and
* the importable package ``memdiver.vol3plugins`` used by MemDiver in-process.

Import-time rule (enforced by ``tests/test_vol3plugins_import_rules.py``, planned): at module level,
every file in this tree may import only the Python standard library and ``volatility3``.
MemDiver itself (~0.9 s to import) and optional accelerators such as ``cryptography`` are
imported lazily inside ``run()``, ``stack()`` or a loader function, behind
``try/except ImportError`` with a pure-Python fallback where one exists. That keeps
``vol -p <this dir> -h`` as fast as stock ``vol -h``.

Class paths: Volatility saves a layer as ``<module>.<class>`` and finds it again only through
``sys.modules``. A layer class therefore needs one name in both contexts. ``msl_layer.py``
gives its layers the vol-side name ``volatility3.plugins.msl_layer`` even when MemDiver
imports it as ``memdiver.vol3plugins.msl_layer``, so a config saved either way replays
under ``vol -p <this dir> -c config.json``. Any new layer module here needs the same.
"""
