"""Recipe v2 (``architect/vol3_recipe.py``): data model, rendering, guards, builder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.architect import vol3_recipe as vr
from tests import _vol3_recipe_fixtures as fx

pytest.importorskip("cryptography")


# -- data model ---------------------------------------------------------------

def test_recipe_json_round_trip_is_lossless():
    recipe = fx.synthetic_recipe()
    text = recipe.to_json()
    again = vr.PluginRecipe.from_json(text)
    assert again == recipe
    assert again.to_json() == text
    assert json.loads(text)["schema"] == vr.SCHEMA_ID


def test_recipe_from_dict_rejects_other_schema():
    data = fx.synthetic_recipe().to_dict()
    data["schema"] = "memdiver-vol3-recipe/1"
    with pytest.raises(vr.RecipeError, match="schema"):
        vr.PluginRecipe.from_dict(data)


def test_recipe_names_must_be_identifiers():
    with pytest.raises(vr.RecipeError, match="identifier"):
        vr.PluginRecipe("bad-name", "Cls", "", (vr.Locator("entropy", {}),),
                        vr.Decoder(0, 32))


def test_oracle_sample_cap_and_hash_are_enforced():
    with pytest.raises(vr.RecipeError, match="cap"):
        vr.OracleSample.from_bytes(bytes(vr.SAMPLE_INLINE_MAX + 1))
    good = vr.OracleSample.from_bytes(b"abc")
    with pytest.raises(vr.RecipeError, match="sha256"):
        vr.OracleSample(inline_b64=good.inline_b64, sha256="0" * 64)
    with pytest.raises(vr.RecipeError, match="XOR"):
        vr.OracleSample()


def test_decoder_rejects_unimplemented_layouts():
    with pytest.raises(vr.RecipeError, match="candidate_layout"):
        vr.Decoder(0, 32, candidate_layout="split")


# -- locator kinds --------------------------------------------------------------

def test_unknown_locator_kind_is_refused_at_construction():
    with pytest.raises(vr.RecipeError, match="unknown locator kind"):
        vr.Locator("telepathy", {})


@pytest.mark.parametrize("kind", vr.RESERVED_LOCATORS)
def test_reserved_locator_is_recognised_but_not_renderable(kind):
    recipe = vr.PluginRecipe("memdiver_x", "MemDiverSynthX", "",
                             (vr.Locator(kind, {}),), vr.Decoder(0, 32))
    assert vr.PluginRecipe.from_json(recipe.to_json()) == recipe
    with pytest.raises(vr.UnimplementedLocatorError, match=kind):
        vr.render(recipe)


# -- rendering --------------------------------------------------------------------

def test_render_is_deterministic():
    recipe = fx.synthetic_recipe()
    first = vr.render(recipe)
    assert first == vr.render(recipe)
    assert first == vr.render(vr.PluginRecipe.from_json(recipe.to_json()))
    assert "class MemDiverSynthGocryptfs(" in first
    assert "@@" not in first


def test_render_without_oracle_has_empty_bundle():
    source = vr.render(fx.synthetic_recipe(with_oracle=False))
    assert "MEMDIVER_INLINED_SOURCES = ''" in source


# -- degenerate-anchor guard --------------------------------------------------------

def _zero_anchor_recipe():
    tokens = " ".join(["00"] * 64 + ["??"] * 32 + ["00"] * 32)
    return fx.synthetic_recipe(pattern=tokens)


def test_degenerate_anchor_is_refused_when_strict(tmp_path):
    with pytest.raises(vr.DegenerateAnchorError, match="degenerate"):
        vr.emit(_zero_anchor_recipe(), None, tmp_path)
    assert not list(tmp_path.iterdir())


def test_degenerate_anchor_is_a_diagnostic_when_not_strict(tmp_path):
    result = vr.emit(_zero_anchor_recipe(), None, tmp_path, strict_anchors=False)
    assert [d["code"] for d in result.diagnostics] == ["vol3_recipe.degenerate_anchor"]
    assert result.diagnostics[0]["details"]["distinct_bytes"] == 1
    assert result.path.is_file()


def test_structured_anchor_is_not_degenerate():
    quality = vr.anchor_quality(fx.synthetic_recipe().locators[0])
    assert not quality["degenerate"]
    assert quality["distinct_bytes"] > 20


# -- emit + self-test -----------------------------------------------------------------

def test_emit_writes_plugin_recipe_and_rule_and_self_tests(tmp_path):
    pytest.importorskip("volatility3")
    recipe = fx.synthetic_recipe()
    result = vr.emit(recipe, fx.process_buffer(), tmp_path,
                     expected_offset=fx.KEY_SITES[0])
    assert result.path == tmp_path / "memdiver_gocryptfs_synth.py"
    assert result.path.read_text() == result.source
    recipe_file = tmp_path / "memdiver_gocryptfs_synth.recipe.json"
    assert vr.PluginRecipe.from_json(recipe_file.read_text()) == recipe
    assert result.yara_path is not None and "rule " in result.yara_path.read_text()
    assert result.self_test.found and result.self_test.proven == 2
    assert result.self_test.expected_offset_reported is True


# -- builder from (synthetic) real data ------------------------------------------------

def _two_runs(tmp_path):
    """Two captures of the 'same program' holding two DIFFERENT keys."""
    dumps = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER)):
        dump = tmp_path / f"proc_{label}.bin"
        dump.write_bytes(fx.process_buffer(master))
        dumps.append(dump)
    return dumps, [fx.MASTER.hex(), fx.OTHER_MASTER.hex()]


def test_recipe_from_located_key_wildcards_key_and_proves(tmp_path):
    pytest.importorskip("volatility3")
    dumps, keys = _two_runs(tmp_path)
    vault_dir = fx.write_vault(tmp_path / "cipher")
    recipe, extras = vr.recipe_from_located_key(
        dumps, keys, oracle_kind=fx.KIND, oracle_sample_path=vault_dir,
        context=64, name="memdiver_gocryptfs_built")
    anchor = recipe.locators[0].params["pattern"].split()
    key_span = anchor[recipe.decoder.key_offset:recipe.decoder.key_offset + 32]
    assert key_span == ["??"] * 32
    recipe_json = recipe.to_json()
    assert fx.MASTER.hex() not in recipe_json and fx.OTHER_MASTER.hex() not in recipe_json
    assert recipe.locators[1].params["step"] == 8
    assert recipe.provenance["mask_windows"] == 4
    assert str(tmp_path) not in recipe_json, "provenance must not carry absolute paths"
    assert [d["name"] for d in recipe.provenance["dumps"]] == ["proc_a.bin", "proc_b.bin"]
    codes = {d["code"]: d["severity"] for d in extras["diagnostics"]}
    assert codes == {"vol3_recipe.high_entropy_constant": "info"}
    result = vr.emit(recipe, extras["reference_data"], tmp_path / "out",
                     expected_offset=extras["expected_offset"])
    assert result.self_test.proven >= 1
    assert result.self_test.expected_offset_reported is True


def test_single_key_high_entropy_context_is_refused_unless_allowed(tmp_path):
    """The 32-byte constant beside the key could be a secret when only ONE key is seen."""
    dump = tmp_path / "proc.bin"
    dump.write_bytes(fx.process_buffer())
    with pytest.raises(vr.HighEntropyContextError, match="allow_high_entropy_context"):
        vr.recipe_from_located_key([dump], fx.MASTER.hex(), oracle_kind=None)
    _recipe, extras = vr.recipe_from_located_key(
        [dump], fx.MASTER.hex(), oracle_kind=None, allow_high_entropy_context=True)
    codes = {d["code"]: d["severity"] for d in extras["diagnostics"]}
    assert codes["vol3_recipe.high_entropy_context"] == "warning"
    assert codes["vol3_recipe.single_dump"] == "warning"


def test_high_entropy_static_runs_detects_random_but_not_structure():
    mask = [True] * 96
    structured = bytes(fx.PREFIX[:32]) * 3
    assert vr.high_entropy_static_runs(structured, mask) == []
    assert vr.high_entropy_static_runs(fx.CONSTANT * 3, mask) == [(0, 96)]


def test_recipe_from_located_key_flags_a_sample_that_does_not_prove(tmp_path):
    dumps, keys = _two_runs(tmp_path)
    vault_dir = fx.write_vault(tmp_path / "cipher", master=fx.OTHER_MASTER)
    _recipe, extras = vr.recipe_from_located_key(
        dumps, keys, oracle_kind=fx.KIND, oracle_sample_path=vault_dir)
    codes = [d["code"] for d in extras["diagnostics"]]
    assert "vol3_recipe.sample_does_not_prove_key" in codes


def test_sample_directory_walk_is_bounded(tmp_path):
    deep = tmp_path / "v" / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "f").write_bytes(b"x")
    with pytest.raises(vr.RecipeError, match="deeper"):
        vr.build_oracle_sample(fx.KIND, tmp_path / "v")


@pytest.mark.parametrize("pattern, match", [
    ("zz " + "?? " * 40, "invalid tokens"),
    (" ".join(["??"] * 96), "no static byte"),
    (" ".join(["00"] * 8 + ["??"] * 32), "outside"),
])
def test_render_validates_anchor_tokens(pattern, match):
    with pytest.raises(vr.RecipeError, match=match):
        vr.render(fx.synthetic_recipe(pattern=pattern))


def test_recipe_from_located_key_refuses_an_absent_key(tmp_path):
    dump = tmp_path / "proc.bin"
    dump.write_bytes(fx.process_buffer())
    with pytest.raises(vr.RecipeError, match="none of the supplied dumps"):
        vr.recipe_from_located_key([dump], fx.OTHER_MASTER.hex(), oracle_kind=None)


# -- opener: where the builder opens its dumps --------------------------------------------

ENC_KEY = bytes(range(32))
ENC_KM = {"key": ENC_KEY, "passphrase": None, "kem_private_key": None}


def _encrypted_runs(tmp_path):
    """Two ENCRYPTED ``.msl`` captures holding two different keys (one container key)."""
    from memdiver.msl.enums import ArchType, OSType
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    dumps = []
    for label, master in (("a", fx.MASTER), ("b", fx.OTHER_MASTER)):
        path = tmp_path / f"enc_{label}.msl"
        writer = MslWriter(path, pid=4242, os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                           encryption=MslEncryptionConfig(raw_key=ENC_KEY))
        writer.add_memory_region(0x7F0000000000, fx.process_buffer(master))
        writer.add_end_of_capture()
        writer.write()
        dumps.append(path)
    return dumps, [fx.MASTER.hex(), fx.OTHER_MASTER.hex()]


@pytest.fixture
def opened(monkeypatch):
    """Names of the dumps ``open_dump`` was called for, per caller module."""
    from memdiver.core import dump_source
    from memdiver.engine import key_location

    seen = {"locate": [], "read": []}
    for module, step in ((key_location, "locate"), (dump_source, "read")):
        real = module.open_dump

        def counting(path, _real=real, _step=step, **kwargs):
            seen[_step].append(Path(path).name)
            return _real(path, **kwargs)
        monkeypatch.setattr(module, "open_dump", counting)
    return seen


@pytest.fixture
def full_passes(monkeypatch):
    """Dumps whose whole-file AEAD tag pass ran (``verify_tag_streaming`` in the reader)."""
    from memdiver.msl import reader as reader_mod

    passes = []
    real = reader_mod.verify_tag_streaming

    def counting(*args, **kwargs):
        passes.append(1)
        return real(*args, **kwargs)
    monkeypatch.setattr(reader_mod, "verify_tag_streaming", counting)
    return passes


def test_default_opener_opens_each_dump_once_per_step(tmp_path, opened):
    dumps, keys = _two_runs(tmp_path)
    vr.recipe_from_located_key(dumps, keys, oracle_kind=None)
    assert opened["locate"] == ["proc_a.bin", "proc_b.bin"]
    # the windows (one open per dump), then the reference slice of the first capture
    assert opened["read"] == ["proc_a.bin", "proc_b.bin", "proc_a.bin"]


def test_a_pooled_opener_decrypts_each_dump_once_for_the_whole_build(tmp_path, full_passes):
    from memdiver.app.key_material import KeyedSources

    dumps, keys = _encrypted_runs(tmp_path)
    unpooled, _ = vr.recipe_from_located_key(dumps, keys, oracle_kind=None,
                                             key_material=ENC_KM)
    assert len(full_passes) == 5  # locate 2 + windows 2 + reference slice 1
    full_passes.clear()
    with KeyedSources(ENC_KM) as pool:
        pooled, extras = vr.recipe_from_located_key(dumps, keys, oracle_kind=None,
                                                    key_material=ENC_KM, opener=pool.opener)
    assert len(full_passes) == 2  # one per dump, across locate + windows + reference slice
    assert pooled == unpooled and extras["expected_offset"] > 0


def test_locate_windows_and_reference_slice_each_take_the_opener(tmp_path, opened):
    from contextlib import nullcontext

    from memdiver.core.dump_source import RawDumpSource

    dumps, keys = _two_runs(tmp_path)
    sources = {str(p): RawDumpSource(p) for p in dumps}
    for source in sources.values():
        source.open()
    calls = []

    def opener(path, **kwargs):
        calls.append(Path(path).name)
        return nullcontext(sources[str(path)])
    try:
        occurrences = vr.locate_occurrences([str(p) for p in dumps],
                                            [bytes.fromhex(k) for k in keys], opener=opener)
        vr._read_windows(occurrences, 32, 64, view=None, key_material=None, opener=opener)
        vr._reference_slice(occurrences[0], 32, None, None, opener=opener)
    finally:
        for source in sources.values():
            source.close()
    assert calls == ["proc_a.bin", "proc_b.bin"] * 2 + ["proc_a.bin"]
    assert opened == {"locate": [], "read": []}


# -- static oracle ctx (OracleSpec.ctx) ---------------------------------------------

def test_oracle_ctx_round_trips_and_is_omitted_when_empty():
    plain = fx.synthetic_recipe()
    assert "ctx" not in plain.to_dict()["oracle"], "old recipes stay byte-identical"
    data = plain.to_dict()
    data["oracle"]["ctx"] = {"hash": "sha256", "min": 2}
    recipe = vr.PluginRecipe.from_dict(data)
    assert recipe.oracle.ctx == {"hash": "sha256", "min": 2}
    assert vr.PluginRecipe.from_json(recipe.to_json()) == recipe
    source = vr.render(recipe)
    embedded = json.loads(source.split("RECIPE_JSON = r'''", 1)[1].split("'''", 1)[0])
    assert embedded["oracle"]["ctx"] == {"hash": "sha256", "min": 2}


@pytest.mark.parametrize("ctx, match", [
    ({"found": []}, "run time"),
    ({"read": 1}, "run time"),
    ({"blob": b"\x00"}, "JSON"),
    ({"x": float("nan")}, "JSON"),
])
def test_oracle_ctx_refuses_runtime_keys_and_non_json(ctx, match):
    with pytest.raises(vr.RecipeError, match=match):
        vr.OracleSpec(fx.KIND, {}, None, ctx)


def test_oracle_spec_builder_threads_the_ctx_into_the_sample_check(monkeypatch, tmp_path):
    seen = {}

    def fake_verify(kind, params, blob, key, ctx=None):
        seen["ctx"] = ctx
        return {"status": "proven", "detail": ""}
    monkeypatch.setattr(vr, "_verify_sample", fake_verify)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(fx.sample())
    spec = vr._oracle_spec(fx.KIND, sample, {}, fx.MASTER, [], ctx={"hint": 1})
    assert spec.ctx == {"hint": 1} and seen["ctx"] == {"hint": 1}
    assert vr._oracle_spec(fx.KIND, None, {}, fx.MASTER, []).ctx == {}


# -- F3: dump digests are memoized per file identity --------------------------------

@pytest.fixture
def hashed(monkeypatch):
    """Count sha256_streamed calls; start from an empty digest cache."""
    from memdiver.core import artifact_util

    calls = []
    real = artifact_util.sha256_streamed

    def counting(path):
        calls.append(Path(path).name)
        return real(path)
    monkeypatch.setattr(artifact_util, "sha256_streamed", counting)
    monkeypatch.setattr(vr, "_DIGEST_CACHE", type(vr._DIGEST_CACHE)())
    return calls


def test_dump_digests_hash_once_then_come_from_the_cache(tmp_path, hashed):
    import hashlib
    import os

    dump = tmp_path / "a.bin"
    dump.write_bytes(b"memory" * 100)
    link = tmp_path / "link.bin"
    os.symlink(dump, link)
    first = vr._dump_digests([str(dump)])
    assert first == [hashlib.sha256(b"memory" * 100).hexdigest()]
    assert vr._dump_digests([str(dump), str(link)]) == first * 2
    assert hashed == ["a.bin"], "second call and the symlink must not re-read the dump"


def test_dump_digests_rehash_after_a_size_or_mtime_change(tmp_path, hashed):
    import os

    dump = tmp_path / "a.bin"
    dump.write_bytes(b"x" * 10)
    before = vr._dump_digests([str(dump)])[0]
    stat = dump.stat()
    os.utime(dump, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10 ** 9))
    assert vr._dump_digests([str(dump)])[0] == before
    dump.write_bytes(b"y" * 11)
    after = vr._dump_digests([str(dump)])[0]
    assert after != before
    assert hashed == ["a.bin"] * 3


def test_dump_digest_cache_is_bounded(tmp_path, hashed, monkeypatch):
    monkeypatch.setattr(vr, "_DIGEST_CACHE_MAX", 2)
    paths = []
    for i in range(3):
        path = tmp_path / f"d{i}.bin"
        path.write_bytes(bytes([i]) * 8)
        paths.append(str(path))
    for path in paths:                      # one by one: a deterministic eviction order
        vr._dump_digests([path])
    assert len(vr._DIGEST_CACHE) == 2
    vr._dump_digests([paths[0]])           # evicted (oldest) -> hashed again
    assert hashed.count("d0.bin") == 2
