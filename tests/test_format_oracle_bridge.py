"""Format oracles wired into the BYO-oracle stage (C1).

Covers ``engine/resources/format_oracle.py`` (adapter, sample packing),
the lazy ``format:<kind>`` registration in ``builtin_oracle``, the registry's
``add_format`` (+ arm / dry-run / smoke-test unchanged), the three producers in
``app/tools_format_oracle.py`` and ``app.oracle_autoconfig.suggest_format_oracle``.
All on real LUKS headers written by cryptsetup (``tests/fixtures/luks``).
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.api.services.oracle_registry import (
    OracleConfigInvalid,
    OracleRegistry,
    get_oracle_registry,
    init_oracle_registry,
    reset_oracle_registry,
)
from memdiver.app import oracle_autoconfig, tools_format_oracle
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.resources import builtin_oracle, format_oracle
from memdiver.engine.resources.format_oracle import (
    FormatOracleAdapter,
    format_oracle_config,
    load_format_sample,
)

REPO = Path(__file__).resolve().parent.parent
LUKS = REPO / "tests" / "fixtures" / "luks"
EXPECTED_KINDS = {
    "aead-generic", "gocryptfs-gcm", "luks", "ssh-kdf-consistency",
    "x25519-dh-consistency", "x25519-pubkey", "xts-fsmagic",
}


def _gt_key(name: str) -> bytes:
    for line in (LUKS / f"{name}.gt.txt").read_text().splitlines():
        if line.startswith("volume_key_hex="):
            return bytes.fromhex(line.split("=", 1)[1].strip())
    raise AssertionError(f"no volume key in {name}.gt.txt")


def _wrong_key(length: int = 64) -> bytes:
    """High-entropy and wrong: passes the LUKS prefilter, fails the digest."""
    return bytes((i * 89 + 7) % 256 for i in range(length))


# -- adapter -----------------------------------------------------------------


@pytest.mark.parametrize("name", ["luks1-xts", "luks2-default", "luks1-essiv"])
def test_adapter_proves_the_volume_key_and_rejects_others(name):
    sample = load_format_sample("luks", LUKS / f"{name}.hdr.bin")
    adapter = FormatOracleAdapter("luks", {}, sample)
    key = _gt_key(name)

    assert adapter.verify(key) is True
    assert adapter.last_verdict.status == "proven"
    assert adapter.verify(_wrong_key(len(key))) is False
    assert adapter.last_verdict.status == "rejected"
    assert adapter.unique is True and len(key) in adapter.candidate_lengths


def test_adapter_runs_the_prefilter_before_verify():
    adapter = FormatOracleAdapter("luks", {}, load_format_sample("luks", LUKS / "luks1-xts.hdr.bin"))
    assert adapter.verify(bytes(64)) is False
    assert adapter.last_verdict.detail.startswith("prefilter: ")


def test_adapter_reports_error_for_non_bytes_without_raising():
    adapter = FormatOracleAdapter("luks", {}, load_format_sample("luks", LUKS / "luks1-xts.hdr.bin"))
    assert adapter.verify(object()) is False  # type: ignore[arg-type]
    assert adapter.last_verdict.status == "error"


def test_adapter_turns_a_raising_oracle_into_an_error_verdict(monkeypatch):
    adapter = FormatOracleAdapter("luks", {}, load_format_sample("luks", LUKS / "luks1-xts.hdr.bin"))

    def boom(candidate, ctx):
        raise RuntimeError("bug")

    monkeypatch.setattr(adapter._oracle, "verify", boom)
    monkeypatch.setattr(adapter._oracle, "prefilter", lambda c: None)
    assert adapter.verify(_wrong_key()) is False
    assert adapter.last_verdict.status == "error" and "bug" in adapter.last_verdict.detail


def test_adapter_rejects_unknown_kind_and_bad_params():
    with pytest.raises(ValueError, match="no oracle format"):
        FormatOracleAdapter("nope", {}, b"x")
    with pytest.raises(ValueError, match="params must be a mapping"):
        FormatOracleAdapter("luks", ["x"], b"x")  # type: ignore[arg-type]


def test_adapter_close_is_safe_without_oracle_close():
    adapter = FormatOracleAdapter("luks", {}, load_format_sample("luks", LUKS / "luks1-xts.hdr.bin"))
    adapter.close()


# -- samples -----------------------------------------------------------------


def test_luks_raw_header_is_packed_and_a_ready_sample_passes_through(tmp_path):
    packed = load_format_sample("luks", LUKS / "luks2-default.hdr.bin")
    assert packed[:1] == b"{" and len(packed) <= 8192  # compact LUKS2 JSON
    ready = tmp_path / "s.bin"
    ready.write_bytes(packed)
    assert load_format_sample("luks", ready) == packed


def test_sample_errors_name_the_path(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        load_format_sample("luks", tmp_path / "missing")
    with pytest.raises(ValueError, match="is a directory"):
        load_format_sample("luks", tmp_path)


def test_sample_source_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(format_oracle, "MAX_SAMPLE_SOURCE_BYTES", 10)
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 11)
    with pytest.raises(ValueError, match="at most 10 bytes"):
        load_format_sample("x25519-pubkey", big)


def test_gocryptfs_sample_from_vault_dir_and_content_file(tmp_path):
    from memdiver.oracles import get_format

    module = get_format("gocryptfs-gcm")
    vault = tmp_path / "vault"
    (vault / "sub").mkdir(parents=True)
    (vault / "gocryptfs.conf").write_text(json.dumps(
        {"FeatureFlags": ["GCMIV128", "HKDF", "DirIV", "EMENames", "LongNames", "Raw64"]}))
    (vault / "gocryptfs.diriv").write_bytes(os.urandom(16))
    content = bytes([0, 2]) + os.urandom(16) + os.urandom(16 + 64 + 16)
    (vault / "sub" / "file").write_bytes(content)
    (vault / "AAAA").write_bytes(content)

    from_dir = load_format_sample("gocryptfs-gcm", vault)
    from_file = load_format_sample("gocryptfs-gcm", vault / "sub" / "file")
    assert from_dir.startswith(module.SAMPLE_MAGIC)
    assert from_file == from_dir  # same bytes, conf found two levels up
    meta = module.parse_sample(from_file)["meta"]
    assert "HKDF" in meta["feature_flags"]


def test_gocryptfs_dir_without_content_files_is_refused(tmp_path):
    (tmp_path / "gocryptfs.conf").write_text("{}")
    with pytest.raises(ValueError, match="no usable encrypted gocryptfs content file"):
        load_format_sample("gocryptfs-gcm", tmp_path)


def test_decode_sample_b64_is_strict():
    with pytest.raises(ValueError, match="not valid base64"):
        format_oracle.decode_sample_b64("!!!")
    with pytest.raises(ValueError, match="zero bytes"):
        format_oracle.decode_sample_b64("")


def test_format_oracle_config_is_self_contained(tmp_path):
    config, adapter = format_oracle_config("luks", sample_path=str(LUKS / "luks1-xts.hdr.bin"))
    adapter.close()
    assert config["resource_type"] == "format:luks"
    assert config["sample_source"].endswith("luks1-xts.hdr.bin")
    rebuilt = builtin_oracle.build_oracle({**config, "sample_source": "/gone"})
    assert rebuilt.verify(_gt_key("luks1-xts")) is True
    with pytest.raises(ValueError, match="not both"):
        format_oracle_config("luks", sample_path="a", sample_b64="b")


def test_factory_reads_sample_path_and_rejects_bad_ctx():
    factory = format_oracle.format_resource_factory("luks")
    adapter = factory({"sample_path": str(LUKS / "luks1-xts.hdr.bin")})
    assert adapter.verify(_gt_key("luks1-xts")) is True
    with pytest.raises(ValueError, match="ctx must be a mapping"):
        factory({"sample_path": str(LUKS / "luks1-xts.hdr.bin"), "ctx": [1]})


def test_kind_and_resource_type_helpers():
    assert format_oracle.resource_type_for("luks") == "format:luks"
    assert format_oracle.kind_of("format:luks") == "luks"
    assert format_oracle.kind_of("tls-pcap") is None
    assert format_oracle.kind_of("format:") is None


def test_describe_format_reports_static_facts():
    facts = format_oracle.describe_format("luks")
    assert facts["unique"] is True and 64 in facts["candidate_lengths"]
    assert format_oracle.describe_format("x25519-pubkey")["unique"] is False
    assert set(format_oracle.list_format_kinds()) == EXPECTED_KINDS


# -- builtin_oracle registration ---------------------------------------------


def test_format_types_register_lazily_and_first_party():
    assert builtin_oracle.is_registered_resource_type("format:luks")
    assert builtin_oracle.is_first_party_resource_type("format:gocryptfs-gcm")
    names = builtin_oracle.register_format_resource_types()
    assert {n.split(":", 1)[1] for n in names} == EXPECTED_KINDS
    assert not builtin_oracle.is_registered_resource_type("format:nope")


def test_build_oracle_returns_the_adapter_not_a_resource_oracle():
    config, adapter = format_oracle_config("luks", sample_path=str(LUKS / "luks1-xts.hdr.bin"))
    adapter.close()
    oracle = builtin_oracle.build_oracle(config)
    assert isinstance(oracle, FormatOracleAdapter)


def test_registration_never_overrides_an_existing_factory(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(builtin_oracle, "_FORMAT_TYPES_REGISTERED", False)
    monkeypatch.setitem(builtin_oracle.RESOURCE_FACTORIES, "format:luks", sentinel)
    builtin_oracle.register_format_resource_types()
    assert builtin_oracle.RESOURCE_FACTORIES["format:luks"] is sentinel


def test_importing_builtin_oracle_does_not_import_the_formats():
    code = ("import sys, memdiver.engine.resources.builtin_oracle;"
            "print('memdiver.oracles' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True, cwd=str(REPO))
    assert out.stdout.strip() == "False"


def test_load_oracle_on_the_builtin_path_builds_the_adapter():
    from memdiver.engine.oracle import load_oracle

    config, adapter = format_oracle_config("luks", sample_path=str(LUKS / "luks2-default.hdr.bin"))
    adapter.close()
    verify = load_oracle(builtin_oracle.BUILTIN_ORACLE_PATH, config, sandbox=False)
    assert verify(_gt_key("luks2-default")) is True
    assert verify(_wrong_key()) is False


# -- producers ---------------------------------------------------------------


def test_list_format_oracles_result_lists_all_seven():
    payload = tools_format_oracle.list_format_oracles_result().payload
    assert payload["count"] == 7
    assert {f["kind"] for f in payload["formats"]} == EXPECTED_KINDS
    for row in payload["formats"]:
        assert {"candidate_lengths", "cost_us", "sample_kind", "unique"} <= set(row)


def test_spec_result_grades_without_echoing_candidates():
    key = _gt_key("luks1-xts")
    payload = tools_format_oracle.format_oracle_spec_result(
        "luks", oracle_sample_path=str(LUKS / "luks1-xts.hdr.bin"),
        candidates_hex=[key.hex(), _wrong_key().hex()],
    ).payload
    assert [r["status"] for r in payload["graded"]] == ["proven", "rejected"]
    assert payload["proven"] == 1
    assert key.hex() not in json.dumps(payload["graded"])
    assert payload["oracle_path"] == builtin_oracle.BUILTIN_ORACLE_PATH
    assert payload["oracle_config"]["resource_type"] == "format:luks"


def test_spec_result_errors_are_capability_errors():
    with pytest.raises(CapabilityError, match="could not be built"):
        tools_format_oracle.format_oracle_spec_result("nope")
    with pytest.raises(CapabilityError, match="not hex"):
        tools_format_oracle.format_oracle_spec_result(
            "luks", oracle_sample_path=str(LUKS / "luks1-xts.hdr.bin"), candidates_hex=["zz"])
    with pytest.raises(CapabilityError, match="at most"):
        tools_format_oracle.format_oracle_spec_result(
            "luks", oracle_sample_path=str(LUKS / "luks1-xts.hdr.bin"),
            candidates_hex=["00"] * (tools_format_oracle.MAX_GRADED_CANDIDATES + 1))


def test_spec_result_accepts_sample_b64():
    blob = load_format_sample("luks", LUKS / "luks1-xts.hdr.bin")
    payload = tools_format_oracle.format_oracle_spec_result(
        "luks", sample_b64=base64.b64encode(blob).decode(),
        candidates_hex=[_gt_key("luks1-xts").hex()]).payload
    assert payload["proven"] == 1 and payload["sample_bytes"] == len(blob)


def test_suggest_result_missing_dump_is_not_found(tmp_path):
    with pytest.raises(CapabilityError) as info:
        tools_format_oracle.suggest_format_oracle_result(str(tmp_path / "missing"))
    assert info.value.status == 404


# -- suggest ------------------------------------------------------------------


def _vault_run(tmp_path: Path) -> Path:
    run = tmp_path / "dataset" / "run_0001"
    vault = run / "cipher"
    vault.mkdir(parents=True)
    (vault / "gocryptfs.conf").write_text(json.dumps({"FeatureFlags": ["GCMIV128", "HKDF"]}))
    (vault / "gocryptfs.diriv").write_bytes(os.urandom(16))
    (vault / "content").write_bytes(bytes([0, 2]) + os.urandom(16 + 16 + 64 + 16))
    (run / "meta.json").write_text(json.dumps({
        "run_id": 1, "cipher": "aes", "master_key_hex": "00" * 32,
        "vault_cipher_dir": "run_0001/cipher", "dumps": {}}))
    dump = run / "gdb_raw.bin"
    dump.write_bytes(os.urandom(256))
    return dump


def test_suggest_from_vault_names_the_sample_and_reason(tmp_path):
    suggestion, reason = oracle_autoconfig.suggest_format_oracle(_vault_run(tmp_path))
    assert suggestion is not None and suggestion.kind == "gocryptfs-gcm"
    assert suggestion.confidence == "high" and suggestion.signal == "vault"
    assert suggestion.sample_path.endswith("cipher")  # the vault dir, conf included
    assert "content" in reason and "vault" in reason and suggestion.to_dict()["sample_needed"] is None


def test_suggest_vault_without_packable_file_still_names_the_kind(tmp_path):
    dump = _vault_run(tmp_path)
    (dump.parent / "cipher" / "content").write_bytes(b"\x00\x02short")
    suggestion, _ = oracle_autoconfig.suggest_format_oracle(dump)
    assert suggestion.kind == "gocryptfs-gcm" and suggestion.sample_path is None
    assert suggestion.confidence == "medium" and suggestion.sample_needed


def test_suggest_none_names_every_signal(tmp_path):
    dump = tmp_path / "x.bin"
    dump.write_bytes(b"\0" * 64)
    suggestion, reason = oracle_autoconfig.suggest_format_oracle(dump)
    assert suggestion is None
    assert "meta.json" in reason and "KEY_HINT" in reason and "process" in reason


def test_suggest_unreadable_msl_signal_is_reported_not_raised(tmp_path):
    from memdiver.msl.enums import FILE_MAGIC

    dump = tmp_path / "broken.msl"
    dump.write_bytes(FILE_MAGIC + b"\0" * 8)
    suggestion, reason = oracle_autoconfig.suggest_format_oracle(dump)
    assert suggestion is None and "unreadable" in reason


class _Hint:
    def __init__(self, key_type=0, protocol=0, note="", confidence=2):
        self.key_type, self.protocol, self.note, self.confidence = key_type, protocol, note, confidence


@pytest.mark.parametrize("hint, kind", [
    (_Hint(key_type=0x000A), "ssh-kdf-consistency"),
    (_Hint(key_type=0x000B), "x25519-pubkey"),
    (_Hint(protocol=0x0007), "ssh-kdf-consistency"),
    (_Hint(note="dm-crypt volume key"), "luks"),
    (_Hint(note="VeraCrypt"), "xts-fsmagic"),
    (_Hint(note="gocryptfs master"), "gocryptfs-gcm"),
    (_Hint(protocol=0x0002), None),  # TLS: never a format oracle
])
def test_hint_kind_mapping(hint, kind):
    assert oracle_autoconfig._hint_kind(hint)[0] == kind


def test_suggest_from_key_hint_uses_hint_confidence(tmp_path, monkeypatch):
    dump = tmp_path / "h.msl"
    from memdiver.msl.enums import FILE_MAGIC
    dump.write_bytes(FILE_MAGIC)
    monkeypatch.setattr(oracle_autoconfig, "_msl_blocks",
                        lambda path, collector: [_Hint(key_type=0x000A, confidence=1)]
                        if collector == "collect_key_hints" else [])
    suggestion, reason = oracle_autoconfig.suggest_format_oracle(dump)
    assert suggestion.kind == "ssh-kdf-consistency" and suggestion.confidence == "medium"
    assert suggestion.signal == "key_hint" and "SSH_SESSION_KEY" in reason


@pytest.mark.parametrize("name, base", [
    ("/lib/aarch64-linux-gnu/libssh.so.4", "libssh"),
    ("/usr/bin/gocryptfs", "gocryptfs"),
    ("/usr/sbin/sshd -D", "sshd"),
    ("", ""),
])
def test_program_basename(name, base):
    assert oracle_autoconfig.program_basename(name) == base


def test_suggest_from_modules_on_the_libssh_sample(tmp_path):
    import gzip
    import shutil

    src = REPO / "samples" / "ssh_libssh_client.msl.gz"
    dump = tmp_path / "ssh_libssh_client.msl"
    with gzip.open(src) as fin, dump.open("wb") as fout:
        shutil.copyfileobj(fin, fout)
    suggestion, reason = oracle_autoconfig.suggest_format_oracle(dump)
    assert suggestion.kind == "ssh-kdf-consistency" and suggestion.signal == "process"
    assert "libssh" in reason and suggestion.sample_path is None


# -- registry + REST ----------------------------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router

    init_oracle_registry(oracle_dir=None, examples_dir=REPO / "docs" / "oracle" / "examples")
    app = FastAPI()
    app.include_router(router, prefix="/api/oracles")
    try:
        yield TestClient(app)
    finally:
        reset_oracle_registry()


def _luks_run(tmp_path: Path, name: str = "luks2-default") -> Path:
    key = _gt_key(name)
    run = tmp_path / "ds" / "run_0001"
    run.mkdir(parents=True)
    filler = bytes((i * 131 + 17) % 256 for i in range(64 * 1024))
    (run / "mem.bin").write_bytes(filler[:4096] + key + filler[4096:])
    (run / "meta.json").write_text(json.dumps(
        {"run_id": 1, "cipher": "aes-xts", "master_key_hex": key.hex(), "dumps": {}}))
    return run / "mem.bin"


def test_rest_list_formats(client):
    body = client.get("/api/oracles/formats").json()
    assert body["count"] == 7 and {f["kind"] for f in body["formats"]} == EXPECTED_KINDS


def test_rest_add_arm_dry_run_smoke_test_delete(client, tmp_path):
    key = _gt_key("luks2-default")
    added = client.post("/api/oracles/formats/luks",
                        json={"oracle_sample_path": str(LUKS / "luks2-default.hdr.bin")})
    assert added.status_code == 200, added.text
    entry = added.json()
    assert entry["armed"] is False and entry["format_kind"] == "luks" and entry["shape"] == 2
    oid = entry["id"]

    armed = client.post(f"/api/oracles/{oid}/arm", json={"sha256": entry["sha256"]})
    assert armed.status_code == 200, armed.text and armed.json()["armed"] is True

    dry = client.post(f"/api/oracles/{oid}/dry-run", json={"samples_b64": [
        base64.b64encode(key).decode(), base64.b64encode(_wrong_key()).decode()]}).json()
    assert [r["ok"] for r in dry["results"]] == [True, False]

    smoke = client.post(f"/api/oracles/{oid}/smoke-test", json={
        "source_paths": [str(_luks_run(tmp_path))], "key_size": 64, "seed": 7}).json()
    assert smoke["positive"]["ok"] is True
    assert smoke["negatives"]["rejected"] >= 1 and smoke["negatives"]["accepted"] == 0
    assert smoke["verdict"] == "discriminates"

    assert client.delete(f"/api/oracles/{oid}").status_code == 200
    assert Path(builtin_oracle.BUILTIN_ORACLE_PATH).is_file()  # the module survives


def test_rest_add_bad_sample_is_400(client, tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a header")
    response = client.post("/api/oracles/formats/luks", json={"oracle_sample_path": str(junk)})
    assert response.status_code == 400 and "could not be built" in response.json()["detail"]


def test_rest_suggest(client, tmp_path):
    body = client.post("/api/oracles/formats/suggest",
                       json={"dump_path": str(_vault_run(tmp_path))}).json()
    assert body["suggestion"]["kind"] == "gocryptfs-gcm" and body["reason"]


def test_dry_run_reports_error_verdicts_as_errors(tmp_path, monkeypatch):
    from memdiver.oracles import OracleVerdict

    reg = OracleRegistry(oracle_dir=None, examples_dir=tmp_path)
    entry = reg.add_format("luks", sample_path=str(LUKS / "luks1-xts.hdr.bin"))
    monkeypatch.setattr(FormatOracleAdapter, "_judge",
                        lambda self, c: OracleVerdict("error", "luks", "no backend"))
    result = reg.dry_run(entry.oracle_id, samples=[_wrong_key()])
    assert result["errors"] == 1 and "FormatVerdictError" in result["results"][0]["error"]


def test_registry_format_entry_is_not_persisted(tmp_path):
    reg = OracleRegistry(oracle_dir=tmp_path / "o", examples_dir=tmp_path)
    reg.add_format("luks", sample_path=str(LUKS / "luks1-xts.hdr.bin"))
    assert list((tmp_path / "o").iterdir()) == []
    assert not (Path(builtin_oracle.BUILTIN_ORACLE_PATH).with_suffix(".json")).exists()


def test_registry_add_format_bad_kind(tmp_path):
    reg = OracleRegistry(oracle_dir=None, examples_dir=tmp_path)
    with pytest.raises(OracleConfigInvalid, match="no oracle format"):
        reg.add_format("nope")


def test_add_format_respects_the_read_sandbox(tmp_path, monkeypatch):
    from memdiver.api import path_policy

    monkeypatch.setattr(path_policy, "allowed_roots", lambda: [tmp_path.resolve()])
    reg = OracleRegistry(oracle_dir=None, examples_dir=tmp_path)
    with pytest.raises(CapabilityError) as info:
        reg.add_format("luks", sample_path=str(LUKS / "luks1-xts.hdr.bin"))
    assert info.value.code == "path.outside_sandbox"


def test_singleton_reset_leaves_no_registry():
    reset_oracle_registry()
    with pytest.raises(RuntimeError):
        get_oracle_registry()
