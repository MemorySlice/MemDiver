"""C-IMP1: every vol3plugins/ module must be import-safe inside Volatility 3.

Module-level imports may only be stdlib (Python 3.8 set), ``volatility3`` or
sibling modules of ``vol3plugins/``. Lazy imports inside functions are free.
"""
import ast
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PLUGINS_DIR = REPO / "vol3plugins"
FORBIDDEN = ("memdiver", "cryptography", "numpy", "yara", "Crypto")
# FIXED Python 3.8 stdlib allow-list (not sys.stdlib_module_names, which would
# admit 3.9+ modules that break a plugin on an older Volatility host).
PY38_STDLIB_ALLOWED = frozenset({
    "abc", "array", "ast", "base64", "binascii", "bisect", "codecs", "collections",
    "contextlib", "copy", "ctypes", "dataclasses", "datetime", "enum", "errno",
    "functools", "hashlib", "heapq", "hmac", "importlib", "inspect", "io",
    "itertools", "json", "linecache", "logging", "math", "mmap", "operator", "os",
    "pathlib", "re", "secrets", "string", "struct", "sys", "textwrap", "types",
    "typing", "warnings", "zlib", "__future__",
    "argparse", "bz2", "fnmatch", "glob", "gzip", "lzma", "numbers", "pkgutil",
    "platform", "pprint", "queue", "random", "shutil", "socket", "stat",
    "statistics", "tempfile", "threading", "time", "traceback", "urllib", "uuid",
    "weakref", "zipfile",
})
ALLOWED_ROOTS = PY38_STDLIB_ALLOWED | {"volatility3"}


def _plugin_files():
    return sorted(PLUGINS_DIR.rglob("*.py"))


def _module_level_imports(node):
    """Imports executed at import time: not inside function or class bodies."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(child, ast.Import):
            for alias in child.names:
                yield child, alias.name
        elif isinstance(child, ast.ImportFrom):
            yield child, child.module or ""
        yield from _module_level_imports(child)


def import_violations(source, path=None):
    """Return human-readable violations for module-level imports in ``source``."""
    path = path or PLUGINS_DIR / "_synthetic.py"
    problems = []
    for node, name in _module_level_imports(ast.parse(source)):
        level = getattr(node, "level", 0)
        if level:
            depth = len(path.parent.relative_to(PLUGINS_DIR).parts)
            if level - 1 > depth:
                problems.append("line %d: relative import escapes vol3plugins/" % node.lineno)
            continue
        top = name.split(".")[0]
        if top in FORBIDDEN or top not in ALLOWED_ROOTS:
            problems.append("line %d: module-level import of %r" % (node.lineno, name))
    return problems


def test_discovers_plugin_files():
    names = {p.name for p in _plugin_files()}
    assert {"msl_layer.py", "memdiver_stackers.py"} <= names


@pytest.mark.parametrize("path", _plugin_files(), ids=lambda p: str(p.relative_to(PLUGINS_DIR)))
def test_module_level_imports_are_stdlib_volatility_or_sibling(path):
    problems = import_violations(path.read_text(encoding="utf-8"), path)
    assert problems == [], "%s: %s" % (path.relative_to(REPO), problems)


def test_checker_flags_module_level_memdiver_and_accepts_lazy():
    assert import_violations("import memdiver\n")
    assert import_violations("try:\n    from memdiver.core import x\nexcept ImportError:\n    pass\n")
    assert import_violations("if True:\n    import numpy\n")
    for banned in ("cryptography", "yara", "Crypto.Cipher", "requests"):
        assert import_violations("import %s\n" % banned)
    assert import_violations("import memdiver.core\n")
    assert import_violations("import zoneinfo\n")  # 3.9+ stdlib
    assert import_violations("from .. import x\n")  # escapes vol3plugins/ from the root
    assert import_violations("def f():\n    import memdiver\n") == []
    assert import_violations("class C:\n    def m(self):\n        import cryptography\n") == []
    assert import_violations("import struct\nfrom volatility3.framework import interfaces\nfrom . import sib\n") == []


_VOL = shutil.which("vol")
_DRIVER = """
import sys
import volatility3.plugins
import volatility3.framework as fw
from volatility3 import framework
plugins_dir = sys.argv[1]
volatility3.plugins.__path__ = [plugins_dir] + list(volatility3.plugins.__path__)
fw.import_files(volatility3.plugins, True)
print([m for m in sys.modules if m.split('.')[0] == 'memdiver'])
"""


@pytest.mark.skipif(_VOL is None, reason="`vol` (volatility3) is not on PATH")
def test_vol_help_with_plugin_dir_is_fast():
    times = []
    for _ in range(3):
        start = time.perf_counter()
        proc = subprocess.run([_VOL, "-p", str(PLUGINS_DIR), "-h"], capture_output=True,
                              text=True, timeout=120)
        times.append(time.perf_counter() - start)
        assert proc.returncode == 0, proc.stderr[-2000:]
    assert min(times) < 1.5, "vol -p vol3plugins -h best-of-3 %.2fs (all: %s)" % (min(times), times)


def test_importing_plugins_the_vol_way_does_not_import_memdiver():
    pytest.importorskip("volatility3")
    proc = subprocess.run([sys.executable, "-I", "-c", _DRIVER, str(PLUGINS_DIR)],
                          capture_output=True, text=True, timeout=300, cwd="/")
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.strip().splitlines()[-1] == "[]", proc.stdout[-2000:]
