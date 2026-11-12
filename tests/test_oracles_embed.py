"""Inlining format oracles verbatim into single-file plugins.

The decisive tests run the inlined code the way a generated plugin will: in a
fresh ``python -I`` subprocess, from a temporary directory, with ``memdiver``
poisoned in ``sys.modules`` so any hidden dependency on the repository fails
loudly instead of being satisfied by the editable install.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import subprocess
import sys
import types
from pathlib import Path

import pytest

from memdiver.oracles import embed, get_format
from memdiver.oracles.embed import (
    BUNDLE_SOURCES_NAME,
    extract_inlined,
    inline_module,
    inline_source,
    load_inlined,
    read_paste_safe_source,
    render_bundle,
    verify_inlined,
)
from memdiver.oracles.formats import gocryptfs_gcm as g
from tests._oracle_gocryptfs_fixtures import (
    FEATURE_FLAGS,
    GOCRYPTFS_CORPUS,
    HAVE_CORPUS,
    RUN_0001_MASTER_HEX,
    conf_json,
    content_key_ref,
    encrypt_file,
)

POISON = 'import sys; sys.modules["memdiver"] = None  # inlined code must not need memdiver\n'
# A bare `pip install volatility3`: neither crypto library is importable either.
POISON_ALL = (
    "import sys\n"
    'for _blocked in ("memdiver", "cryptography", "Crypto"):\n'
    "    sys.modules[_blocked] = None\n"
)

_FAKE_FORMAT = '''"""Fake format {kind} for the namespacing test."""
KIND = "{kind}"
CANDIDATE_LENGTHS = (4,)
COST_US = 1
SAMPLE_KIND = "nothing"
REQUIRES_PRIMITIVES = {requires!r}


def _secret():
    return "{kind}"


def make_sample():
    return b""


class _Oracle:
    def verify(self, candidate, ctx):
        prim = globals().get("fakeprim")
        return {{"status": "proven", "kind": KIND, "detail": _secret(),
                 "derived": {{"prim": prim.tag() if prim else None}}}}


def build_oracle(params, sample):
    return _Oracle()
'''


def _proof_case() -> tuple[bytes, bytes]:
    """(sample, master key): real run_0001 when the corpus exists, else synthetic."""
    if HAVE_CORPUS:
        sample = g.sample_from_vault(str(GOCRYPTFS_CORPUS / "run_0001" / "cipher"))
        return sample, bytes.fromhex(RUN_0001_MASTER_HEX)
    pytest.importorskip("cryptography")
    master = bytes(range(32))
    data = encrypt_file("aes-gcm", content_key_ref(master, "aes-gcm"), b"synthetic vault file\n")
    return g.make_sample(data, conf_json(FEATURE_FLAGS["aes-gcm"])), master


def _proof_cases() -> list[tuple[str, bytes, bytes]]:
    """(cipher, sample, master) for aes-gcm and xchacha: corpus runs, else synthetic."""
    if HAVE_CORPUS:
        from tests._oracle_gocryptfs_fixtures import corpus_runs, run_meta

        runs = [corpus_runs(cipher)[0] for cipher in ("aes", "xchacha")]
        return [(run_meta(r)["cipher"], g.sample_from_vault(str(r / "cipher")),
                 bytes.fromhex(run_meta(r)["master_key_hex"])) for r in runs]
    pytest.importorskip("cryptography")
    master, cases = bytes(range(32)), []
    for cipher in ("aes-gcm", "xchacha"):
        data = encrypt_file(cipher, content_key_ref(master, cipher), b"synthetic vault file\n")
        cases.append((cipher, g.make_sample(data, conf_json(FEATURE_FLAGS[cipher])), master))
    return cases


def _run_isolated(tmp_path: Path, name: str, text: str) -> str:
    script = tmp_path / name
    script.write_text(text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", script.name],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ------------------------------------------------------- single inlined oracle


def test_inlined_block_is_the_exact_file_and_its_sha256():
    inlined = inline_source("gocryptfs-gcm")
    file_bytes = Path(get_format("gocryptfs-gcm").__file__).read_bytes()
    assert inlined.sha256 == hashlib.sha256(file_bytes).hexdigest()
    assert extract_inlined(inlined.source) == [
        ("gocryptfs-gcm", inlined.sha256, file_bytes.decode("utf-8"))
    ]
    assert inlined.source.startswith(f"# --- memdiver oracle:gocryptfs-gcm sha256={inlined.sha256}")
    assert [p.name for p in inlined.primitives] == ["aes", "chacha"]
    for primitive in inlined.primitives:
        primitive_file = embed.default_primitives_dir() / f"{primitive.name}.py"
        assert primitive.sha256 == hashlib.sha256(primitive_file.read_bytes()).hexdigest()
        assert verify_inlined(primitive.source)
    assert verify_inlined(inlined.source)


def test_inlined_text_alone_proves_the_key_in_an_isolated_subprocess(tmp_path):
    sample, master = _proof_case()
    driver = (
        "import base64\n"
        f'SAMPLE = base64.b64decode("{_b64(sample)}")\n'
        "oracle = build_oracle({}, SAMPLE)\n"
        f'KEY = bytes.fromhex("{master.hex()}"); BAD = bytes([KEY[0] ^ 1]) + KEY[1:]\n'
        'print(oracle.verify(KEY, {})["status"], oracle.verify(BAD, {})["status"])\n'
    )
    text = POISON + inline_source("gocryptfs-gcm").source + driver
    assert _run_isolated(tmp_path, "standalone_oracle.py", text).split() == ["proven", "rejected"]


def test_one_changed_character_fails_verification():
    source = inline_source("gocryptfs-gcm").source
    at = source.index("def build_oracle")
    assert verify_inlined(source)
    assert not verify_inlined(source[:at] + "D" + source[at + 1:])


def test_malformed_markers_fail_verification():
    source = inline_source("gocryptfs-gcm").source
    lines = source.split("\n")
    sha = inline_source("gocryptfs-gcm").sha256
    assert not verify_inlined("")
    assert not verify_inlined("\n".join(lines[:-2]) + "\n")  # end marker dropped
    assert not verify_inlined(source.replace(sha, "0" * 64, 1))  # begin/end disagree
    assert not verify_inlined(source.replace(sha, "0" * 64))  # both markers, wrong hash
    assert not verify_inlined(source + "# --- memdiver stray line ---\n")


# ------------------------------------------------------------------- bundle


def test_bundle_loads_the_oracle_in_an_isolated_subprocess(tmp_path):
    sample, master = _proof_case()
    driver = (
        "import base64\n"
        f'fmt = load_inlined("gocryptfs-gcm", {BUNDLE_SOURCES_NAME})\n'
        f'oracle = fmt.build_oracle({{}}, base64.b64decode("{_b64(sample)}"))\n'
        f'status = oracle.verify(bytes.fromhex("{master.hex()}"), {{}})["status"]\n'
        'print(status, verify_inlined(open(__file__, encoding="utf-8").read()))\n'
    )
    text = POISON + render_bundle(["gocryptfs-gcm"]) + driver
    assert _run_isolated(tmp_path, "plugin_like.py", text).split() == ["proven", "True"]


def test_bundle_proves_on_pure_python_with_no_crypto_library(tmp_path):
    """The plugin case that matters: stdlib only, primitives inlined, both corpus ciphers."""
    driver = "import base64\n" + f'fmt = load_inlined("gocryptfs-gcm", {BUNDLE_SOURCES_NAME})\n'
    for cipher, sample, master in _proof_cases():
        driver += (
            f'oracle = fmt.build_oracle({{}}, base64.b64decode("{_b64(sample)}"))\n'
            f'key = bytes.fromhex("{master.hex()}"); bad = bytes([key[0] ^ 1]) + key[1:]\n'
            'print(oracle.cipher, oracle.backend, oracle.verify(key, {})["status"],'
            ' oracle.verify(bad, {})["status"])\n'
        )
    out = _run_isolated(tmp_path, "pure_plugin.py", POISON_ALL + render_bundle(["gocryptfs-gcm"]) + driver)
    assert out.splitlines() == [
        "aes-gcm pure-python proven rejected", "xchacha pure-python proven rejected"]


def test_bundle_proves_aes_siv_and_legacy_gcm_on_pure_python(tmp_path):
    """The two layouts the corpus lacks, sealed here (cryptography), opened stdlib-only."""
    pytest.importorskip("cryptography")
    master = bytes(range(64, 96))
    siv = encrypt_file("aes-siv", content_key_ref(master, "aes-siv"), b"siv vault file\n" * 5)
    legacy = encrypt_file("aes-gcm", master, b"legacy vault file\n" * 5, nonce_len=12)
    cases = [g.make_sample(siv, conf_json(FEATURE_FLAGS["aes-siv"])),
             g.make_sample(legacy, conf_json(["DirIV"]))]
    driver = "import base64\n" + f'fmt = load_inlined("gocryptfs-gcm", {BUNDLE_SOURCES_NAME})\n'
    driver += f'key = bytes.fromhex("{master.hex()}"); bad = key[:31] + bytes([key[31] ^ 1])\n'
    for sample in cases:
        driver += (
            f'oracle = fmt.build_oracle({{}}, base64.b64decode("{_b64(sample)}"))\n'
            'print(oracle.cipher, len(oracle.nonce), oracle.backend,'
            ' oracle.verify(key, {})["status"], oracle.verify(bad, {})["status"])\n'
        )
    out = _run_isolated(tmp_path, "pure_siv_legacy.py", POISON_ALL + render_bundle(["gocryptfs-gcm"]) + driver)
    assert out.splitlines() == [
        "aes-siv 16 pure-python proven rejected", "aes-gcm 12 pure-python proven rejected"]


def test_a_tampered_primitive_block_is_refused():
    bundle = render_bundle(["gocryptfs-gcm"])
    namespace: dict = {}
    exec(compile(bundle, "<bundle>", "exec"), namespace)
    sources = namespace[BUNDLE_SOURCES_NAME]
    at = sources.index("def siv_decrypt")
    tampered = sources[:at] + "#" + sources[at:]  # inside primitive:aes, its markers untouched
    assert not verify_inlined(tampered)
    with pytest.raises(ValueError, match="primitive:aes fails its sha256 check"):
        load_inlined("gocryptfs-gcm", tampered)


def test_each_primitive_is_inlined_exactly_once_ahead_of_the_oracle():
    bundle = render_bundle(["gocryptfs-gcm", "gocryptfs-gcm"])
    blocks = extract_inlined(bundle)
    assert [b.kind for b in blocks] == [
        "runtime:inline-loader", "primitive:aes", "primitive:chacha", "gocryptfs-gcm", "gocryptfs-gcm"]
    for block in blocks[1:3]:
        name = block.kind.split(":")[1]
        file_bytes = (embed.default_primitives_dir() / f"{name}.py").read_bytes()
        assert block.sha256 == hashlib.sha256(file_bytes).hexdigest()
        assert block.text == file_bytes.decode("utf-8")
    assert verify_inlined(bundle)


def test_bundle_blocks_and_load_inlined_integrity_check():
    bundle = render_bundle(["gocryptfs-gcm"])
    assert [b.kind for b in extract_inlined(bundle)] == [
        "runtime:inline-loader", "primitive:aes", "primitive:chacha", "gocryptfs-gcm"]
    namespace: dict = {}
    exec(compile(bundle, "<bundle>", "exec"), namespace)
    sources = namespace[BUNDLE_SOURCES_NAME]
    assert load_inlined("gocryptfs-gcm", sources).KIND == "gocryptfs-gcm"
    with pytest.raises(ValueError, match="sha256"):
        load_inlined("gocryptfs-gcm", sources.replace("COST_US = ", "COST_US = 1 + ", 1))
    with pytest.raises(KeyError, match="no inlined oracle:nope"):
        load_inlined("nope", sources)


def _load_fake_format(directory: Path, kind: str, requires: tuple = ("fakeprim",)):
    path = directory / f"{kind.replace('-', '_')}.py"
    path.write_text(_FAKE_FORMAT.format(kind=kind, requires=requires), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"fake_{kind.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_two_oracles_with_a_shared_primitive_do_not_collide(tmp_path):
    prim_dir = tmp_path / "secrets"
    prim_dir.mkdir()
    (prim_dir / "fakeprim.py").write_text('def tag():\n    return "fakeprim-v1"\n')
    first, second = (
        inline_module(_load_fake_format(tmp_path, kind), primitives_dir=prim_dir)
        for kind in ("fake-a", "fake-b")
    )
    assert [p.name for p in first.primitives] == ["fakeprim"]

    bundle = render_bundle([first, second])
    assert [b.kind for b in extract_inlined(bundle)] == [
        "runtime:inline-loader", "primitive:fakeprim", "fake-a", "fake-b",
    ]
    assert verify_inlined(bundle)

    namespace: dict = {}
    exec(compile(bundle, "<bundle>", "exec"), namespace)
    loaded = {k: load_inlined(k, namespace[BUNDLE_SOURCES_NAME]) for k in ("fake-a", "fake-b")}
    for kind, module in loaded.items():
        verdict = module.build_oracle({}, b"").verify(b"1234", {})
        assert verdict["detail"] == kind  # each oracle sees its own _secret()
        assert verdict["derived"] == {"prim": "fakeprim-v1"}


# ------------------------------------------------------------------ guards


def test_read_paste_safe_source_rejects_unsafe_text(tmp_path):
    cases = {
        "marker.py": b"# --- memdiver oracle:x sha256=0 begin ---\n",
        "crlf.py": b"x = 1\r\n",
        "no_newline.py": b"x = 1",
    }
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
        with pytest.raises(ValueError):
            read_paste_safe_source(tmp_path / name)


def test_raw_string_quote_choice():
    assert embed._raw_string_quote("plain") == "'''"
    assert embed._raw_string_quote("has ''' inside") == '"""'
    with pytest.raises(ValueError):
        embed._raw_string_quote("both ''' and \"\"\"")


def test_missing_declared_primitive_is_a_hard_error(tmp_path):
    prim_dir = tmp_path / "secrets"
    prim_dir.mkdir()
    (prim_dir / "fakeprim.py").write_text('def tag():\n    return "v1"\n')
    module = _load_fake_format(tmp_path, "fake-missing", ("fakeprim", "absentprim"))
    with pytest.raises(embed.MissingPrimitiveError, match="absentprim"):
        inline_module(module, primitives_dir=prim_dir)


def test_two_bundles_in_one_process_keep_their_own_primitives(tmp_path):
    loaded = []
    for version in ("v1", "v2"):
        prim_dir = tmp_path / version
        prim_dir.mkdir()
        (prim_dir / "fakeprim.py").write_text(f'def tag():\n    return "{version}"\n')
        inlined = inline_module(_load_fake_format(tmp_path, "fake-shared"), primitives_dir=prim_dir)
        namespace: dict = {}
        exec(compile(render_bundle([inlined]), "<bundle>", "exec"), namespace)
        loaded.append(load_inlined("fake-shared", namespace[BUNDLE_SOURCES_NAME]))
    first, second = loaded
    assert first is not second  # same oracle block, different bundles: separate modules
    tags = [m.build_oracle({}, b"").verify(b"1234", {})["derived"]["prim"] for m in loaded]
    assert tags == ["v1", "v2"]  # loading bundle 2 did not rebind bundle 1's primitive


def test_default_primitives_dir_follows_the_installed_package(monkeypatch, tmp_path):
    import importlib.util as iu

    installed = tmp_path / "site" / "memdiver" / "vol3plugins"
    (installed / "linux" / "secrets").mkdir(parents=True)
    spec = types.SimpleNamespace(submodule_search_locations=[str(installed)])
    monkeypatch.setattr(iu, "find_spec", lambda name: spec if name == "memdiver.vol3plugins" else None)
    assert embed.default_primitives_dir() == installed / "linux" / "secrets"
    monkeypatch.setattr(iu, "find_spec", lambda name: None)
    assert embed.default_primitives_dir() == embed.REPO_ROOT / "vol3plugins" / "linux" / "secrets"
