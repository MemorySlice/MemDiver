"""Offset priority/trust in ``linux.wireguard`` and ``linux.dmcrypt`` with in-memory BTF.

Trusted memory BTF > exact table entry > derived/nearest.  Untrusted, partial, conflicting or
failing recoveries keep the old table path; ``--btf-method off`` never looks at memory.
The memory side is faked by replacing ``btf_layouts.recover_module_layouts``.
"""

import json
import logging

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import exceptions  # noqa: E402

from memdiver.vol3plugins.linux import btf_layouts, dmcrypt  # noqa: E402
from memdiver.vol3plugins.linux import wireguard as wg  # noqa: E402
from memdiver.vol3plugins.linux.secrets import btf_memory as bm  # noqa: E402
from memdiver.vol3plugins.linux.secrets import offsets as dm_offsets  # noqa: E402
from memdiver.vol3plugins.linux.secrets import wg_offsets  # noqa: E402
from tests.test_vol3plugins_btf_memory import BtfBuilder, _base  # noqa: E402

KVER = "6.8.0-136-generic"
UNKNOWN_KVER = "6.8.0-999-generic"
WG_TABLE = wg_offsets.WG_OFFSETS[("x86_64", KVER)]
DM_TABLE = dm_offsets.DM_CRYPT_OFFSETS[("x86_64", KVER)]


def _recovered(module, members=None, structs=None, method="symbols", missing=(), btf=None):
    return bm.RecoveredLayouts(module, structs or {"dummy": object()}, dict(members or {}), method,
                               "btf-memory:%s via %s (test)" % (module, method), "0" * 64, missing,
                               ["test note"], btf)


@pytest.fixture
def fake_memory(monkeypatch):
    """``answers[module]`` = RecoveredLayouts or an exception; ``calls`` records lookups."""
    answers, calls = {}, []

    def recover(context, kernel, module, structs, method):
        calls.append((module, method))
        answer = answers.get(module, bm.BtfParseError("no BTF for %s" % module))
        if isinstance(answer, BaseException):
            raise answer
        return answer
    monkeypatch.setattr(btf_layouts, "recover_module_layouts", recover)
    return answers, calls


# --------------------------------------------------------------------------- wireguard


class BareWireGuard(wg.WireGuard):
    config = None
    context = None
    open = None


def _wg(method="auto", kver=KVER, offsets=None):
    plugin = object.__new__(BareWireGuard)
    plugin.config = {"kernel": "kernel", "btf_method": method, "offsets": offsets}
    plugin.context, plugin.arch, plugin.kver = object(), "x86_64", kver
    return plugin


def test_wg_trusted_memory_wins_and_counts_as_btf(fake_memory):
    answers, _calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", WG_TABLE.members)
    off = _wg()._load_offsets()
    assert off.source.startswith("btf-memory:wireguard") and set(off.sources.values()) == {"btf-memory"}
    assert off.members == WG_TABLE.members
    assert not off.key_path_guessed() and not off.untrusted_no_oracle()  # PSK may be bound-to-proven-peer


def test_wg_memory_replaces_a_derived_guess_on_an_unknown_kernel(fake_memory):
    answers, _calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", WG_TABLE.members)
    assert "derived" in wg_offsets.lookup_offsets("x86_64", UNKNOWN_KVER).source
    off = _wg(kver=UNKNOWN_KVER)._load_offsets()
    assert off.source.startswith("btf-memory:") and not off.key_path_guessed()


def test_wg_untrusted_scan_only_result_keeps_the_table(fake_memory):
    answers, _calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", WG_TABLE.members, method="scan")
    assert _wg()._load_offsets() is WG_TABLE


def test_wg_partial_memory_keeps_the_table(fake_memory):
    answers, _calls = fake_memory
    partial = {k: v for k, v in WG_TABLE.members.items() if k != "noise_handshake.preshared_key"}
    answers["wireguard"] = _recovered("wireguard", partial)
    assert _wg()._load_offsets() is WG_TABLE
    answers["wireguard"] = _recovered("wireguard", WG_TABLE.members, missing=("cookie",))
    assert _wg()._load_offsets() is WG_TABLE


def test_wg_memory_conflicting_with_table_warns_and_memory_wins(fake_memory, caplog):
    answers, _calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", dict(WG_TABLE.members, **{"wg_peer.handshake": 248}))
    with caplog.at_level(logging.WARNING):
        off = _wg()._load_offsets()
    assert off["wg_peer.handshake"] == 248 and off.sources["wg_peer.handshake"] == "btf-memory"
    assert "differs from the built-in table" in caplog.text and "wg_peer.handshake" in caplog.text


@pytest.mark.parametrize("error", [bm.BtfParseError("bad"), MemoryError(), KeyError("x"),
                                   exceptions.InvalidAddressException("layer", 0, "unreadable")])
def test_wg_failing_recovery_keeps_the_table(fake_memory, caplog, error):
    answers, _calls = fake_memory
    answers["wireguard"] = error
    with caplog.at_level(logging.INFO):
        assert _wg()._load_offsets() is WG_TABLE
    assert "btf-memory wireguard: not used" in caplog.text


def test_wg_btf_method_off_never_reads_memory(fake_memory):
    answers, calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", dict(WG_TABLE.members, **{"wg_peer.handshake": 248}))
    assert _wg(method="off")._load_offsets() is WG_TABLE and calls == []


def test_wg_method_is_passed_through(fake_memory):
    _answers, calls = fake_memory
    _wg(method="both")._load_offsets()
    assert calls == [("wireguard", "both")]


@pytest.mark.parametrize("method, walked", [("auto", "symbols"), ("symbols", "symbols"), ("both", "both"),
                                            ("scan", None), ("off", None)])
def test_consumer_auto_is_walk_only_and_scan_is_not_offered(fake_memory, method, walked):
    """Review 2 #1: consumers never scan uselessly (a scan result can never be used there)."""
    _answers, calls = fake_memory
    _wg(method=method)._load_offsets()
    assert calls == ([("wireguard", walked)] if walked else [])


def test_wg_user_offsets_equal_to_memory_are_btf_confirmed(fake_memory, tmp_path):
    answers, _calls = fake_memory
    answers["wireguard"] = _recovered("wireguard", WG_TABLE.members)
    path = tmp_path / "off.json"
    path.write_text(json.dumps({"noise_handshake.preshared_key": WG_TABLE["noise_handshake.preshared_key"],
                                "wg_peer.handshake": 248}))
    off = _wg(kver=UNKNOWN_KVER, offsets=str(path))._load_offsets()
    assert off.sources["noise_handshake.preshared_key"] == "btf-confirmed"
    assert off.sources["wg_peer.handshake"] == "offsets"
    assert off.sources["noise_keypair.sending"] == "btf-memory"


def test_wg_choose_and_from_memory_are_pure():
    assert wg_offsets.from_memory({}, "x") is None
    memory = wg_offsets.from_memory(WG_TABLE.members, "btf-memory:test")
    assert wg_offsets.choose_offsets(memory, WG_TABLE) == (memory, ())
    assert wg_offsets.choose_offsets(None, WG_TABLE) == (WG_TABLE, ())


# --------------------------------------------------------------------------- dmcrypt


class BareDmCrypt(dmcrypt.DmCrypt):
    config = None
    context = None
    open = None


class FakeVmlinux:
    def __init__(self, dm_builtin=True):
        self.dm_builtin = dm_builtin

    def get_type(self, name):
        if name == "hash_cell" and not self.dm_builtin:
            raise exceptions.SymbolError(name, "kernel", "no such type")
        return object()


def _dm(method="auto", kver=KVER, dm_builtin=True, offsets=None):
    plugin = object.__new__(BareDmCrypt)
    plugin.config = {"kernel": "kernel", "btf_method": method, "offsets": offsets}
    plugin.context, plugin.arch, plugin.kver = object(), "x86_64", kver
    plugin.vmlinux = FakeVmlinux(dm_builtin)
    return plugin


def _dm_crypt_btf(crypt_config=None, flags=None, cipher_flags=None):
    base_builder, ids = _base()
    m = BtfBuilder(base_builder)
    members = crypt_config or DM_TABLE.crypt_config
    m.composite("crypt_config", 888, [(name, ids["int"], 8 * off) for name, off in members.items()])
    if flags is not False:
        m.enum("flags", sorted((flags or DM_TABLE.flag_bits).items(), key=lambda kv: kv[1]))
    m.enum("cipher_flags", sorted((cipher_flags or DM_TABLE.cipher_flag_bits).items(), key=lambda kv: kv[1]))
    split = bm.parse_btf(m.blob(), bm.parse_btf(base_builder.blob()))
    layout = split.struct("crypt_config")
    return _recovered("dm_crypt", bm.flat_offsets([layout]), {"crypt_config": layout}, btf=split)


def test_dm_trusted_memory_wins_with_flag_bits_from_btf(fake_memory):
    answers, _calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf()
    off = _dm()._load_offsets()
    assert dm_offsets.is_memory_source(off) and off.crypt_config == DM_TABLE.crypt_config
    assert off.flag_bits == DM_TABLE.flag_bits and off.cipher_flag_bits == DM_TABLE.cipher_flag_bits
    assert off.dm_core == DM_TABLE.dm_core  # dm core built in: table/ISF, not memory


def test_dm_memory_on_a_kernel_without_a_table_entry(fake_memory):
    answers, _calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf(flags=dict(DM_TABLE.flag_bits, DM_CRYPT_HIGH_PRIORITY=7))
    assert dm_offsets.lookup_offsets("x86_64", "7.9.0") is None
    off = _dm(kver="7.9.0")._load_offsets()
    assert dm_offsets.is_memory_source(off) and off.flag_bits["DM_CRYPT_HIGH_PRIORITY"] == 7


def test_dm_missing_flag_enum_keeps_the_table(fake_memory, caplog):
    answers, _calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf(flags=False)
    with caplog.at_level(logging.INFO):
        assert _dm()._load_offsets() is DM_TABLE
    assert "not used" in caplog.text


def test_dm_partial_crypt_config_keeps_the_table(fake_memory):
    answers, _calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf({k: v for k, v in DM_TABLE.crypt_config.items() if k != "key_size"})
    assert _dm()._load_offsets() is DM_TABLE


def test_dm_conflict_with_table_warns_and_memory_wins(fake_memory, caplog):
    answers, _calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf(dict(DM_TABLE.crypt_config, key_size=216))
    with caplog.at_level(logging.WARNING):
        off = _dm()._load_offsets()
    assert off.crypt_config["key_size"] == 216 and "crypt_config.key_size" in caplog.text


@pytest.mark.parametrize("answer", ["untrusted", "error", "off"])
def test_dm_untrusted_failing_or_off_keeps_the_table(fake_memory, answer):
    answers, calls = fake_memory
    recovered = _dm_crypt_btf()
    recovered.method = "scan"
    answers["dm_crypt"] = recovered if answer == "untrusted" else bm.BtfParseError("bad")
    assert _dm(method="off" if answer == "off" else "auto")._load_offsets() is DM_TABLE
    assert (calls == []) == (answer == "off")


def test_dm_user_offsets_still_win(fake_memory, tmp_path):
    answers, calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf()
    path = tmp_path / "off.json"
    path.write_text(json.dumps({"crypt_config": DM_TABLE.crypt_config}))
    off = _dm(offsets=str(path))._load_offsets()
    assert off.source.startswith("--offsets") and calls == []


def _dm_mod_structs():
    def struct(name, size, members):
        return bm.BtfStruct(name, "struct", size, 1, tuple(
            bm.BtfMember(m, off, off * 8, 0, msize, 0, "t") for m, off, msize in members))
    core = DM_TABLE.dm_core
    return {
        "hash_cell": struct("hash_cell", 96, [(k.split(".")[1], v, 8) for k, v in core.items()
                                             if k.startswith("hash_cell.")]),
        "mapped_device": struct("mapped_device", 512, [
            (k.split(".")[1], v, 16 if k.endswith(".name") else 8) for k, v in core.items()
            if k.startswith("mapped_device.")]),
        "dm_table": struct("dm_table", 256, [(k.split(".")[1], v, 8) for k, v in core.items()
                                             if k.startswith("dm_table.")]),
        "dm_target": struct("dm_target", 80, [(k.split(".")[1], v, 8) for k, v in core.items()
                                              if k.startswith("dm_target.")]),
        "target_type": struct("target_type", 64, [("name", 8, 8)]),
        "dm_dev": struct("dm_dev", 48, [("bdev", 0, 8), ("name", 28, 16)]),
    }


def test_dm_core_from_dm_mod_btf_when_dm_core_is_a_module(fake_memory):
    answers, calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf()
    answers["dm_mod"] = _recovered("dm_mod", structs=_dm_mod_structs())
    plugin = _dm(dm_builtin=False)
    off = plugin._load_offsets()
    assert ("dm_mod", "symbols") in calls and plugin.dm_core_source == "btf-memory"
    for key in ("hash_cell.md", "dm_table.targets", "dm_target.private", "dm_dev.name", "target_type.name"):
        assert off.dm_core[key] == DM_TABLE.dm_core[key]
    assert off.dm_core["sizeof(dm_target)"] == 80 and off.dm_core["sizeof(dm_dev.name)"] == 16


def test_dm_core_not_read_from_memory_when_built_in(fake_memory):
    answers, calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf()
    _dm(dm_builtin=True)._load_offsets()
    assert [c[0] for c in calls] == ["dm_crypt"]


def test_kernel_layout_labels_memory_dm_core():
    class NoDmTypes:
        def get_type(self, name):
            raise exceptions.SymbolError(name, "kernel", "no such type")
    layout = dmcrypt.KernelLayout.from_module(NoDmTypes(), DM_TABLE.dm_core, "btf-memory")
    assert layout.sources["hash_cell.md"] == "btf-memory" and not layout.missing_walk()


def test_dm_from_memory_and_differences_are_pure():
    assert dm_offsets.from_memory({}, {}, {}, "btf-memory:x") is None
    same = dm_offsets.from_memory(DM_TABLE.crypt_config, DM_TABLE.flag_bits, DM_TABLE.cipher_flag_bits,
                                  "btf-memory:x")
    assert dm_offsets.differences(same, DM_TABLE) == () and dm_offsets.is_memory_source(same)
    assert not dm_offsets.is_memory_source(DM_TABLE)


def test_dm_mod_untrusted_while_dm_crypt_trusted_takes_dm_core_from_the_table(fake_memory):
    """Review 2 #6: dm_mod BTF unusable -> dm core from the table, labelled "table"."""
    answers, calls = fake_memory
    answers["dm_crypt"] = _dm_crypt_btf()
    untrusted = _recovered("dm_mod", structs=_dm_mod_structs(), method="scan")
    answers["dm_mod"] = untrusted
    plugin = _dm(dm_builtin=False)
    off = plugin._load_offsets()
    assert dm_offsets.is_memory_source(off) and off.dm_core == DM_TABLE.dm_core
    assert plugin.dm_core_source == "table" and [c[0] for c in calls] == ["dm_crypt", "dm_mod"]


def test_dm_core_filled_for_user_offsets_without_a_dm_core_section(fake_memory, tmp_path):
    """Review 2 #3: --offsets without dm_core on a dm_mod-module kernel -> trusted dm_mod BTF."""
    answers, _calls = fake_memory
    answers["dm_mod"] = _recovered("dm_mod", structs=_dm_mod_structs())
    path = tmp_path / "off.json"
    path.write_text(json.dumps({"crypt_config": DM_TABLE.crypt_config}))
    plugin = _dm(offsets=str(path), dm_builtin=False)
    off = plugin._load_offsets()
    assert off.source.startswith("--offsets") and off.dm_core["hash_cell.md"] == DM_TABLE.dm_core["hash_cell.md"]
    assert plugin.dm_core_source == "btf-memory"


def test_dm_flags_enum_is_the_one_with_dm_crypt_names(fake_memory):
    """Review 2 #5: another module-local ``enum flags`` must not be picked."""
    answers, _calls = fake_memory
    recovered = _dm_crypt_btf()
    base_builder, ids = _base()
    m = BtfBuilder(base_builder)
    m.enum("flags", [("OTHER_A", 0), ("OTHER_B", 9)])  # first, unrelated
    m.composite("crypt_config", 888, [(n, ids["int"], 8 * o) for n, o in DM_TABLE.crypt_config.items()])
    m.enum("flags", sorted(DM_TABLE.flag_bits.items(), key=lambda kv: kv[1]))
    m.enum("cipher_flags", sorted(DM_TABLE.cipher_flag_bits.items(), key=lambda kv: kv[1]))
    split = bm.parse_btf(m.blob(), bm.parse_btf(base_builder.blob()))
    recovered = _recovered("dm_crypt", structs={"crypt_config": split.struct("crypt_config")}, btf=split)
    answers["dm_crypt"] = recovered
    assert _dm()._load_offsets().flag_bits == DM_TABLE.flag_bits
    assert dmcrypt._named_enum(split, "flags", "DM_CRYPT_") == DM_TABLE.flag_bits
    with pytest.raises(bm.BtfParseError):
        dmcrypt._named_enum(split, "flags", "NOPE_")


def test_dm_flag_bits_out_of_range_are_refused():
    assert dm_offsets.from_memory(DM_TABLE.crypt_config, dict(DM_TABLE.flag_bits, DM_CRYPT_SAME_CPU=64),
                                  DM_TABLE.cipher_flag_bits, "btf-memory:x") is None
    assert dm_offsets.from_memory(DM_TABLE.crypt_config, DM_TABLE.flag_bits,
                                  dict(DM_TABLE.cipher_flag_bits, CRYPT_IV_LARGE_SECTORS=-1), "btf-memory:x") is None


def test_hide_table_switch_is_test_only_and_warns_once(monkeypatch, caplog):
    """Review 2 #2."""
    assert wg_offsets.HIDE_TABLE_ENV == dm_offsets.OFFSETS_HIDE_TABLE_ENV == "MEMDIVER_TEST_HIDE_OFFSET_TABLE"
    monkeypatch.setenv(wg_offsets.HIDE_TABLE_ENV, "1")
    monkeypatch.setattr(wg_offsets, "_TABLE_HIDDEN_WARNED", [])
    with caplog.at_level(logging.WARNING):
        wg_offsets.lookup_offsets("x86_64", KVER)
        wg_offsets.lookup_offsets("x86_64", KVER)
    assert caplog.text.count("TEST ONLY") == 1


# --------------------------------------------------------------------------- shared helper


def test_recover_trusted_returns_none_for_off_and_no_context(fake_memory):
    _answers, calls = fake_memory
    assert btf_layouts.recover_trusted(object(), "kernel", "wireguard", ("wg_peer",), "off") is None
    assert btf_layouts.recover_trusted(None, "kernel", "wireguard", ("wg_peer",), "auto") is None
    assert calls == []


def test_btf_method_requirement_choices():
    requirement = btf_layouts.btf_method_requirement()
    assert requirement.name == "btf_method" and set(requirement.choices) == {"auto", "symbols", "both", "off"}
    assert "walk only" in requirement.description
    names = {r.name for r in wg.WireGuard.get_requirements()} & {r.name for r in dmcrypt.DmCrypt.get_requirements()}
    assert "btf_method" in names


# --------------------------------------------------------------------------- real capture (gated)


@pytest.mark.parametrize("plugin", ["wireguard", "dmcrypt"])
def test_real_x86_capture_with_the_table_hidden_uses_memory_btf(tmp_path, monkeypatch, plugin):
    """Stock vol, built-in table entry hidden: the in-memory BTF alone must give today's proofs."""
    import shutil
    import sys
    from pathlib import Path

    from tests import test_vol3plugins_linux_dmcrypt as dm_tests
    from tests import test_vol3plugins_linux_wireguard as wg_tests
    vol = shutil.which("vol") or str(Path(sys.executable).with_name("vol"))
    tests = wg_tests if plugin == "wireguard" else dm_tests
    if not (tests._capture_present(tests.X86_STEM) and Path(vol).is_file()):
        pytest.skip("x86_64 capture or stock `vol` not present")
    monkeypatch.setenv(wg_offsets.HIDE_TABLE_ENV, "1")  # inherited by the vol subprocess
    if plugin == "wireguard":
        wg_tests._run_and_check(tmp_path, [vol], wg_tests.X86_STEM)
    else:
        dm_tests._run_capture(tmp_path, dm_tests.X86_STEM, [vol])
