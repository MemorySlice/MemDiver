"""The recipe-v2 plugin template (``architect/templates/vol3_plugin_v2.py.tmpl``).

Checks the generated plugin as an artefact (imports, inlined oracle hashes,
a golden pin of the template part) and RUNS it: in-process over synthetic
buffers via ``engine.vol3_verify.run_over_buffer``, and -- when the real
gocryptfs corpus and ``vol`` are present -- under stock Volatility 3.

Golden regen (after an intended template change)::

    MEMDIVER_REGEN_GOLDEN=1 python -m pytest tests/test_vol3_plugin_v2_template.py -k golden
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.architect import vol3_recipe as vr
from memdiver.oracles import embed
from memdiver.oracles.formats import gocryptfs_gcm
from tests import _vol3_recipe_fixtures as fx
from tests._oracle_gocryptfs_fixtures import GOCRYPTFS_CORPUS, HAVE_CORPUS, RUN_0001_MASTER_HEX

pytest.importorskip("cryptography")

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "fixtures" / "vol3_plugin_pin" / "v2_gocryptfs_plugin.py.golden"
BUNDLE_PLACEHOLDER = "# <memdiver inlined oracle bundle: pinned separately>\nMEMDIVER_INLINED_SOURCES = ''\n"


@pytest.fixture(scope="module")
def source() -> str:
    return vr.render(fx.synthetic_recipe())


def _run(source, data, **config):
    pytest.importorskip("volatility3")
    from memdiver.engine.vol3_verify import run_over_buffer

    return run_over_buffer(source, data, extra_config=config or None)


def _rows(source, data, **config):
    pytest.importorskip("volatility3")
    from memdiver.engine.vol3_verify import run_rows_over_buffer

    return run_rows_over_buffer(source, data, extra_config=config or None)


# -- the generated file as an artefact ----------------------------------------------

def _top_level_imports(tree):
    for node in tree.body:
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import in a generated plugin"
            yield node.module or ""


def test_module_level_imports_are_stdlib_and_volatility3_only(source):
    tree = ast.parse(source)
    roots = {name.split(".")[0] for name in _top_level_imports(tree)}
    assert "volatility3" in roots
    foreign = {r for r in roots - {"volatility3"} if r not in sys.stdlib_module_names}
    assert not foreign, foreign
    every_import = {
        (n.module or "") if isinstance(n, ast.ImportFrom) else a.name
        for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [None])
    }
    assert not any(name.startswith("memdiver") for name in every_import)


def test_inlined_oracle_verifies_and_matches_the_repository(source):
    assert embed.verify_inlined(source)
    blocks = {b.kind: b for b in embed.extract_inlined(source)}
    repo_sha = hashlib.sha256(Path(gocryptfs_gcm.__file__).read_bytes()).hexdigest()
    assert blocks[fx.KIND].sha256 == repo_sha


def test_golden_pin_of_the_template_part():
    rendered = vr.render(fx.synthetic_recipe(), bundle=BUNDLE_PLACEHOLDER)
    if os.environ.get("MEMDIVER_REGEN_GOLDEN"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(rendered, encoding="utf-8")
    assert rendered == GOLDEN.read_text(encoding="utf-8"), (
        "template output changed; if intended, regenerate with "
        "MEMDIVER_REGEN_GOLDEN=1 python -m pytest tests/test_vol3_plugin_v2_template.py -k golden")


def test_plugin_imports_and_proves_with_only_stdlib_and_volatility3(source, tmp_path):
    """No memdiver, no cryptography, no pycryptodome: the inlined primitives prove the key."""
    pytest.importorskip("volatility3")
    plugin = tmp_path / "memdiver_pure_plugin.py"
    plugin.write_text(source, encoding="utf-8")
    script = (
        "import base64, importlib.util, sys\n"
        'for blocked in ("memdiver", "cryptography", "Crypto"):\n'
        "    sys.modules[blocked] = None\n"
        "spec = importlib.util.spec_from_file_location('memdiver_pure_plugin', sys.argv[1])\n"
        "plugin = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(plugin)\n"
        "spec = plugin.RECIPE['oracle']\n"
        "fmt = plugin.load_inlined(spec['kind'], plugin.MEMDIVER_INLINED_SOURCES)\n"
        "oracle = fmt.build_oracle({}, base64.b64decode(spec['sample']['inline_b64']))\n"
        f"key = bytes.fromhex('{fx.MASTER.hex()}')\n"
        "print(oracle.backend, oracle.verify(key, {})['status'],"
        " oracle.verify(key[::-1], {})['status'])\n"
    )
    result = subprocess.run([sys.executable, "-I", "-c", script, str(plugin)], cwd=tmp_path,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["pure-python", "proven", "rejected"]


# -- in-process runs over synthetic buffers -------------------------------------------

def test_synthetic_key_is_found_and_proven(source):
    report = _run(source, fx.process_buffer())
    assert report.proven_count == 2
    assert {h.key_absolute_offset for h in report.hits} == set(fx.KEY_SITES)
    assert all(h.key_hex == fx.MASTER.hex() for h in report.hits)
    assert all(h.proven == "oracle:gocryptfs-gcm" for h in report.hits)


def test_pure_python_backend_proves_and_warns_once(source, caplog, monkeypatch):
    monkeypatch.setenv("MEMDIVER_PUREPY_CRYPTO", "1")
    caplog.set_level("INFO")
    report = _run(source, fx.process_buffer())
    assert report.proven_count == 2
    assert all(h.proven == "oracle:gocryptfs-gcm" for h in report.hits)
    warnings = [r for r in caplog.records if "pure-Python crypto" in r.getMessage()]
    assert len(warnings) == 1 and warnings[0].levelname == "WARNING"
    assert "pip install cryptography or pycryptodome" in warnings[0].getMessage()


def test_accelerated_backend_is_logged_at_info(source, caplog, monkeypatch):
    monkeypatch.delenv("MEMDIVER_PUREPY_CRYPTO", raising=False)
    caplog.set_level("INFO")
    assert _run(source, fx.process_buffer()).proven_count == 2
    lines = [r for r in caplog.records if "crypto backend" in r.getMessage()]
    assert [(r.levelname, r.getMessage().split(": ")[-1]) for r in lines] == [("INFO", "cryptography")]
    assert "pure-Python" not in caplog.text


def test_wrong_key_is_never_proven(source):
    report = _run(source, fx.process_buffer(master=fx.OTHER_MASTER))
    assert report.proven_count == 0
    assert report.hits, "rejected candidates are previewed when nothing is proven"
    assert {h.proven for h in report.hits} <= {"rejected"}


def test_weak_anchor_adds_candidates_but_no_false_proof():
    """A filler anchor matching everywhere still proves only the real key."""
    weak = " ".join(["00"] * 8 + ["??"] * (len(fx.PREFIX) - 8) + ["??"] * 32)
    source = vr.render(fx.synthetic_recipe(pattern=weak))
    data = fx.process_buffer(master=fx.OTHER_MASTER)
    report = _run(source, data, exhaustive=True, show_unverified=True)
    assert report.proven_count == 0
    assert report.match_count > 10


def test_entropy_locator_proves_when_the_anchor_is_absent(source):
    rows = _rows(source, fx.process_buffer(with_anchor=False))
    proven = [r for r in rows if r["Proven"] == "oracle:gocryptfs-gcm"]
    assert {r["KeyOffset"] for r in proven} == set(fx.KEY_SITES)
    assert all(r["Detail"].startswith("via entropy") for r in proven)


def test_without_any_sample_candidates_are_unverified():
    source = vr.render(fx.synthetic_recipe(with_oracle=False))
    report = _run(source, fx.process_buffer())
    assert report.proven_count == 0
    assert {h.proven for h in report.hits} == {"unverified"}


@pytest.mark.parametrize("cipher", ["aes-gcm", "xchacha"])
def test_oracle_sample_override_with_a_vault_dir_autodetects_cipher(tmp_path, cipher):
    source = vr.render(fx.synthetic_recipe(oracle_sample=fx.sample("aes-gcm", fx.OTHER_MASTER)))
    vault_dir = fx.write_vault(tmp_path / "cipher", cipher)
    report = _run(source, fx.process_buffer(), oracle_sample=str(vault_dir))
    assert report.proven_count == 2
    assert "%s block 0 authenticated" % cipher in json.dumps(
        _rows(source, fx.process_buffer(), oracle_sample=str(vault_dir)))


def test_oracle_sample_override_with_a_packed_sample_file(tmp_path):
    source = vr.render(fx.synthetic_recipe(oracle_sample=fx.sample("aes-gcm", fx.OTHER_MASTER)))
    blob = tmp_path / "sample.bin"
    blob.write_bytes(fx.sample("aes-gcm"))
    assert _run(source, fx.process_buffer(), oracle_sample=str(blob)).proven_count == 2


def test_v2_emit_plugin_for_hit(tmp_path):
    """``engine.vol3_emit.emit_plugin_for_hit(template="v2", oracle=...)``."""
    pytest.importorskip("volatility3")
    from memdiver.engine.vol3_emit import emit_plugin_for_hit
    from memdiver.engine.vol3_verify import run_over_buffer

    data = fx.process_buffer()
    site = fx.KEY_SITES[0]
    start = site - len(fx.PREFIX)
    variance = [0.0] * len(fx.PREFIX) + [9000.0] * 32 + [0.0] * 32
    hit = {"offset": site, "length": 32, "neighborhood_start": start,
           "neighborhood_variance": variance}
    oracle = vr.OracleSpec(fx.KIND, {}, vr.OracleSample.from_bytes(fx.sample())).to_dict()
    path = emit_plugin_for_hit(hit, data, "memdiver_hit_v2", tmp_path / "memdiver_hit_v2.py",
                               template="v2", oracle=oracle)
    assert path.with_suffix(".recipe.json").is_file()
    assert path.with_suffix(".yar").is_file()
    assert run_over_buffer(path.read_text(), data).proven_count == 2
    with pytest.raises(ValueError, match="template"):
        emit_plugin_for_hit(hit, data, "x", tmp_path / "x.py", template="v3")


# -- real corpus under stock vol -------------------------------------------------------

@pytest.mark.skipif(not HAVE_CORPUS, reason="gocryptfs corpus not present")
@pytest.mark.skipif(shutil.which("vol") is None, reason="stock `vol` not on PATH")
def test_corpus_run_0001_is_proven_under_stock_vol(tmp_path):
    """Synthesized from runs 1+2 (two keys: the 32-byte constant beside the key
    is then provably a program constant), run ALONE under stock vol on run 1."""
    runs = [GOCRYPTFS_CORPUS / "run_0001", GOCRYPTFS_CORPUS / "run_0002"]
    captures = [run / "memslicer.msl" for run in runs]
    if not all(c.is_file() for c in captures):
        pytest.skip("run_0001/run_0002 have no memslicer.msl")
    capture = captures[0]
    keys = [json.loads((run / "meta.json").read_text())["master_key_hex"] for run in runs]
    recipe, extras = vr.recipe_from_located_key(
        captures, keys, oracle_kind=fx.KIND,
        oracle_sample_path=runs[0] / "cipher", name="memdiver_gocryptfs")
    result = vr.emit(recipe, extras["reference_data"], tmp_path / "plugin",
                     expected_offset=extras["expected_offset"])
    assert result.self_test.proven >= 1
    alone = tmp_path / "alone"
    alone.mkdir()
    shutil.copy(result.path, alone / result.path.name)  # the plugin file ALONE
    completed = subprocess.run(
        ["vol", "-q", "-r", "json", "-p", f"{REPO / 'vol3plugins'};{alone}", "-f", str(capture),
         f"{result.path.stem}.{recipe.class_name}"],
        capture_output=True, text=True, timeout=600)
    assert completed.returncode == 0, completed.stderr[-2000:]
    rows = json.loads(completed.stdout)
    proven = [r for r in rows if r["Proven"] == "oracle:gocryptfs-gcm"]
    assert {r["KeyHex"] for r in proven} == {RUN_0001_MASTER_HEX}
    assert {r["KeyOffset"] for r in proven} == {0xC0000BC220, 0xC0000BC4A0}


# -- review fixes: layer requirements, wrong vault, caps, oracle params ------------------

def _plugin_module(source):
    pytest.importorskip("volatility3")
    from memdiver.engine.vol3_verify import load_plugin_class

    cls = load_plugin_class(source, "memdiver_v2_review_%d" % id(source))
    return cls, sys.modules[cls.__module__]


def test_kernel_requirement_comes_first_and_satisfies_primary(source):
    """The stacker fills the FIRST layer requirement; it must be kernel.layer_name."""
    from volatility3.framework import contexts

    cls, _module = _plugin_module(source)
    names = [r.name for r in cls.get_requirements()]
    assert names[:2] == ["kernel", "primary"]
    primary = cls.get_requirements()[1]
    assert not primary.optional, "a mandatory requirement is what makes the stacker run"
    context = contexts.Context()
    assert primary.unsatisfied(context, "plugins.X"), "nothing stacked yet"
    context.config["plugins.X.kernel.layer_name"] = "layer_name"
    assert primary.unsatisfied(context, "plugins.X") == {}


def test_wrong_vault_warns_shows_anchor_first_and_skips_entropy(source, caplog):
    caplog.set_level("WARNING")
    sample = vr.OracleSample.from_bytes(fx.sample("aes-gcm", fx.OTHER_MASTER))
    wrong = vr.render(fx.synthetic_recipe(oracle_sample=sample.blob()))
    rows = _rows(wrong, fx.process_buffer())
    assert rows and all(r["Proven"] == "rejected" for r in rows)
    assert all(r["Detail"].startswith("via anchor") for r in rows), "entropy must not run"
    assert "is --oracle-sample from THIS capture's vault" in caplog.text
    exhaustive = _rows(wrong, fx.process_buffer(), exhaustive=True, show_unverified=True)
    assert exhaustive[0]["Detail"].startswith("via anchor"), "anchor candidates first"
    assert any("entropy" in r["Detail"] for r in exhaustive)


def test_entropy_cap_warns_with_coverage(caplog):
    caplog.set_level("WARNING")
    recipe = fx.synthetic_recipe()
    data = recipe.to_dict()
    data["locators"][1]["params"]["max_candidates"] = 5
    data["locators"][0]["params"]["pattern"] = " ".join(
        ["11"] * 8 + ["??"] * (len(fx.PREFIX) - 8) + ["??"] * 32)  # never matches
    source = vr.render(vr.PluginRecipe.from_dict(data))
    _rows(source, fx.process_buffer())
    assert "entropy locator hit its cap" in caplog.text
    assert "covered only" in caplog.text


def test_raw_content_file_needs_oracle_param_cipher(tmp_path):
    source = vr.render(fx.synthetic_recipe(oracle_sample=fx.sample("aes-gcm", fx.OTHER_MASTER)))
    content, _conf = fx.vault("aes-gcm")
    raw = tmp_path / "content.bin"
    raw.write_bytes(content)
    without = _rows(source, fx.process_buffer(), oracle_sample=str(raw))
    assert without and all(r["Proven"].startswith("error:") for r in without)
    proven = _run(source, fx.process_buffer(), oracle_sample=str(raw),
                  oracle_param=["cipher=aes-gcm"])
    assert proven.proven_count == 2


def test_error_codes_are_whole_words(source):
    _cls, module = _plugin_module(source)
    code = module.error_code("backend 'cryptography' is not installed; xchacha needs it")
    assert code == "error:backend-cryptography-is-not"
    assert len(code) <= len("error:") + module.ERROR_CODE_MAX
    assert module.parse_oracle_params(["cipher=aes-gcm", "hkdf=false", "nonce_length=12"]) == {
        "cipher": "aes-gcm", "hkdf": False, "nonce_length": 12}


def test_oracle_sample_directory_walk_is_bounded(source, tmp_path):
    deep = tmp_path / "v" / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "f").write_bytes(b"x")
    rows = _rows(source, fx.process_buffer(), oracle_sample=str(tmp_path / "v"))
    assert rows and all(r["Proven"] == "error:oracle" for r in rows)
    assert "deeper than 3 levels" in rows[0]["Detail"]


def test_entropy_block_flags_match_the_per_block_rule(source, tmp_path):
    """The constant-page shortcut of ``EntropyScanner`` flags exactly what the per-block rule does."""
    import importlib.util
    import random

    pytest.importorskip("volatility3")
    plugin = tmp_path / "memdiver_flags_plugin.py"
    plugin.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("memdiver_flags_plugin", plugin)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rng = random.Random(7)
    pages = [bytes(4096), b"\xff" * 4096, bytes(rng.randrange(256) for _ in range(4096)),
             b"\x00" * 4095 + b"\x01", bytes(rng.randrange(3) for _ in range(4096))]
    for block, minimum in ((16, 12), (16, 1), (16, 0), (10, 2), (64, 12), (4096, 2)):
        for size_extra in (0, 1, 7, 4095):
            data = b"".join(rng.choice(pages) for _ in range(5)) + bytes(size_extra)
            scanner = module.EntropyScanner(window=1 << 14, threshold=4.5, step=1,
                                            block=block, block_min_distinct=minimum)
            want = [len(set(data[i:i + scanner.block])) >= minimum
                    for i in range(0, len(data) - scanner.block + 1, scanner.block)]
            assert scanner._block_flags(data) == want, (block, minimum, size_extra)
