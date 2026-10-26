"""ISF producers (plan T4.2): draft wrappers on a tmp case, probes via fakes, gated real run."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.app import tools_isf as T
from memdiver.core.service_errors import CapabilityError

CAP = "b" * 64
INT = {"kind": "base", "name": "int"}


def payload(result):
    return result.payload


@pytest.fixture
def case(tmp_path):
    case_dir = str(tmp_path / "case")
    T.isf_draft_create_result(case_dir, CAP, "d", "x86_64", banner="Linux version 5.10")
    return case_dir


def donor(tmp_path, size=64):
    isf = {"metadata": {}, "base_types": {"int": {"size": 4, "signed": True, "kind": "int",
                                                   "endian": "little"}},
           "user_types": {"task": {"kind": "struct", "size": size, "fields": {
               "pid": {"offset": 8, "type": INT}, "comm": {"offset": 16, "type": INT}}}},
           "enums": {}, "symbols": {"init_task": {"address": 0xFFFF000000001000}}}
    path = tmp_path / "donor.isf.json"
    path.write_text(json.dumps(isf))
    return str(path)


def test_create_list_and_duplicate(case):
    listed = payload(T.isf_draft_list_result(case, CAP))
    assert listed["count"] == 1 and listed["drafts"][0]["name"] == "d"
    with pytest.raises(CapabilityError):
        T.isf_draft_create_result(case, CAP, "d", "x86_64")


def test_capture_id_invalid(case):
    with pytest.raises(CapabilityError) as exc:
        T.isf_draft_list_result(case, "nope")
    assert exc.value.code == "capture_id_invalid"


def test_set_ops_and_get_hex(case):
    T.isf_draft_set_result(case, CAP, "d", "symbol", {"name": "init_task", "address": "0xffff0000"},
                           evidence=["x"])
    T.isf_draft_set_result(case, CAP, "d", "struct", {"name": "task", "size": 64})
    T.isf_draft_set_result(case, CAP, "d", "field",
                           {"struct": "task", "field": "pid", "offset": 8, "type": INT})
    T.isf_draft_set_result(case, CAP, "d", "base_type", {
        "name": "int", "size": 4, "signed": True, "kind": "int", "endian": "little"})
    T.isf_draft_set_result(case, CAP, "d", "enum",
                           {"name": "e", "size": 4, "base": "int", "constants": {"A": 1}})
    got = payload(T.isf_draft_get_result(case, CAP, "d"))
    assert got["counts"] == {"base_types": 1, "user_types": 1, "enums": 1, "symbols": 1}
    assert "sections" not in got
    full = payload(T.isf_draft_get_result(case, CAP, "d", only={"symbols": []},
                                          include_origins=True))
    sym = full["sections"]["symbols"]
    assert sym["items"]["init_task"]["address"] == "0xffff0000"
    assert sym["origins"]["init_task"]["provenance"]["evidence"] == ["x"]
    T.isf_draft_set_result(case, CAP, "d", "remove", {"key": ["symbols", "init_task"]})
    assert payload(T.isf_draft_get_result(case, CAP, "d"))["counts"]["symbols"] == 0


def test_set_errors(case):
    with pytest.raises(CapabilityError) as exc:
        T.isf_draft_set_result(case, CAP, "d", "bogus", {})
    assert exc.value.code == "isf_unknown_op"
    with pytest.raises(CapabilityError) as exc:
        T.isf_draft_set_result(case, CAP, "d", "struct", {"name": "x"})
    assert exc.value.code == "isf_missing_args"


def test_get_limit_truncates(case):
    for i in range(5):
        T.isf_draft_set_result(case, CAP, "d", "symbol", {"name": f"s{i}", "address": i})
    got = payload(T.isf_draft_get_result(case, CAP, "d", only={"symbols": []}, limit=2))
    assert got["truncated"] and len(got["sections"]["symbols"]["items"]) == 2


def test_import_retract_versions_export(case, tmp_path):
    imp = payload(T.isf_draft_import_result(case, CAP, "d", donor(tmp_path),
                                            only={"user_types": ["task"]}))
    assert imp["counts"] == {"user_types": 1}
    assert payload(T.isf_draft_get_result(case, CAP, "d"))["counts"]["user_types"] == 1
    T.isf_draft_retract_result(case, CAP, "d", imp["entry"]["entry_id"], reason="oops")
    assert payload(T.isf_draft_get_result(case, CAP, "d"))["counts"]["user_types"] == 0
    versions = payload(T.isf_draft_versions_result(case, CAP, "d"))
    assert versions["total"] == 2 and not versions["truncated"]
    assert any(v["retracted"] for v in versions["versions"])
    out = tmp_path / "out.isf.json"
    exp = payload(T.isf_draft_export_result(case, CAP, "d", out_path=str(out)))
    assert exp["path"] == str(out) and len(exp["sha256"]) == 64 and out.is_file()
    with pytest.raises(CapabilityError):
        T.isf_draft_import_result(case, CAP, "d", str(tmp_path / "missing.json"))


def test_diff_version_and_file(case, tmp_path):
    first = payload(T.isf_draft_set_result(case, CAP, "d", "struct",
                                           {"name": "task", "size": 64}))["entry"]["entry_id"]
    T.isf_draft_set_result(case, CAP, "d", "field",
                           {"struct": "task", "field": "pid", "offset": 8, "type": INT})
    by_version = payload(T.isf_draft_diff_result(case, CAP, "d", against_version=first))
    assert by_version["counts"]["added"] == 1
    by_file = payload(T.isf_draft_diff_result(case, CAP, "d", against_isf=donor(tmp_path),
                                              only={"user_types": ["task"]}, limit=1))
    assert by_file["counts"]["added"] == 0 and by_file["total"] >= 1
    assert by_file["truncated"] == (by_file["total"] > 1)
    with pytest.raises(CapabilityError):
        T.isf_draft_diff_result(case, CAP, "d")


def test_validate_summarizes_plugins(case, tmp_path):
    pytest.importorskip("pakunoda")
    T.isf_draft_import_result(case, CAP, "d", donor(tmp_path))
    out = payload(T.isf_draft_validate_result(case, CAP, "d"))
    assert isinstance(out["is_valid"], bool) and out["plugins"]
    assert sum(out["verdicts"].values()) == len(out["plugins"])


# -- probe (fakes) -------------------------------------------------------------

def test_probe_argument_validation(tmp_path):
    with pytest.raises(CapabilityError) as exc:
        T.isf_probe_result(str(tmp_path / "x"), "nope")
    assert exc.value.code == "isf.unknown_probe"
    with pytest.raises(CapabilityError) as exc:
        T.isf_probe_result(str(tmp_path / "x"), "kallsyms", case_dir=str(tmp_path))
    assert exc.value.code == "isf.draft_target_incomplete"
    with pytest.raises(CapabilityError) as exc:
        T.isf_probe_result(str(tmp_path / "x"), "utsname", case_dir=str(tmp_path), draft="d")
    assert exc.value.code == "isf.probe_not_feedable"
    with pytest.raises(CapabilityError) as exc:
        T.isf_probe_result(str(tmp_path / "x"), "banner")
    assert exc.value.code == "image_not_found"


class FakeSession:
    capture = CAP
    arch_name, arch_source = "x86_64", "banner_string"

    def __init__(self, image, arch, params):
        self.params, self.timings, self.warnings = params, {"open": 0.0}, []
        self.syms = {f"sym{i}": 0xFFFFFFFF81000000 + i * 16 for i in range(10)}

    def close(self):
        pass

    def kallsyms(self):
        return SimpleNamespace(metadata={"num_symbols": 10, "symbols": self.syms})

    def symbols(self):
        return self.syms

    def init_task(self):
        return {"va": 1, "phys": 100, "source": "kallsyms", "probe": {"va": 1, "phys": 2340},
                "disagreement": {"probe_phys": 2340, "derived_phys": 100, "delta": 2240}}


@pytest.fixture
def fake(monkeypatch, tmp_path):
    pytest.importorskip("pakunoda")
    monkeypatch.setattr(T, "_Session", FakeSession)
    image = tmp_path / "img.lime"
    image.write_bytes(b"x")
    return str(image)


def test_kallsyms_probe_sample_truncated_and_draft_gets_all(fake, tmp_path):
    case_dir = str(tmp_path / "case")
    T.isf_draft_create_result(case_dir, CAP, "d", "x86_64")
    out = payload(T.isf_probe_result(fake, "kallsyms", params={"limit": 3},
                                     case_dir=case_dir, draft="d"))
    assert len(out["rows"]) == 3 and out["truncated"] and out["counts"]["symbols"] == 10
    assert out["rows"][0]["location"]["space"] == "kernel_va"
    assert out["imported"]["symbols"] == 10
    assert payload(T.isf_draft_get_result(case_dir, CAP, "d"))["counts"]["symbols"] == 10


def test_init_task_reports_disagreement(fake):
    out = payload(T.isf_probe_result(fake, "init_task"))
    row = out["rows"][0]
    assert row["location"]["space"] == "physical" and row["location"]["value"] == 100
    assert row["disagreement"]["delta"] == 2240
    assert any("disagrees" in w for w in out["warnings"])


def test_derive_init_task_phys_formula():
    s = object.__new__(T._Session)
    s._kallsyms = SimpleNamespace(metadata={"symbols": {
        "init_task": 0xFFFFFFFF82000000, "linux_banner": 0xFFFFFFFF81000000}})
    s._banner = SimpleNamespace(offset=0x2000000)
    assert s._derive_init_task_phys() == 0x2000000 + 0x1000000


def test_hint_types_prefer_draft_then_donor(case, tmp_path):
    store = T._store(case)
    donor_isf = json.loads(Path(donor(tmp_path)).read_text())
    hints = T._hint_types(store, CAP, "d", donor_isf)
    assert hints[("task", "pid")] == INT


# -- arch resolution ------------------------------------------------------------

def _bare_session(tmp_path, *, banner="", elf=None, probes=None, banner_probe=None):
    """A _Session with no dump: only what _resolve_arch touches."""
    image = tmp_path / "i.img"
    image.write_bytes(elf or b"\x00" * 32)
    s = object.__new__(T._Session)
    s.image, s.warnings, s.timings = image, [], {}
    s.banner_text = lambda: banner
    s._arch_from_banner_probe = lambda text: banner_probe
    s.probes, s.dump = probes, object()
    return s


def _probes(verified):
    def find_root(dump, arch, vmcoreinfo=None):
        return SimpleNamespace(verified=arch in verified)
    return SimpleNamespace(resolve_arch=lambda name: name, find_page_table_root=find_root)


def test_resolve_arch_explicit_wins(tmp_path):
    s = _bare_session(tmp_path, banner="Linux version aarch64")
    assert s._resolve_arch("riscv64") == ("riscv64", "explicit")


def test_resolve_arch_banner_string(tmp_path):
    s = _bare_session(tmp_path, banner="Linux version 5.10 x86_64 gcc")
    assert s._resolve_arch("auto") == ("x86_64", "banner_string")


def test_resolve_arch_pakunoda_banner(tmp_path):
    s = _bare_session(tmp_path, banner="mystery banner", banner_probe="aarch64")
    assert s._resolve_arch("auto") == ("aarch64", "pakunoda_banner")


def test_resolve_arch_elf_header(tmp_path):
    head = b"\x7fELF" + b"\x00" * 14 + (0xB7).to_bytes(2, "little") + b"\x00" * 8
    s = _bare_session(tmp_path, elf=head)
    assert s._resolve_arch("auto") == ("aarch64", "elf_header")


def test_resolve_arch_paging_self_test_single_arch(tmp_path):
    s = _bare_session(tmp_path, probes=_probes({"aarch64"}))
    assert s._resolve_arch("auto") == ("aarch64", "paging_self_test")
    assert s.warnings == []


def test_resolve_arch_paging_self_test_ambiguous_is_no_answer(tmp_path):
    s = _bare_session(tmp_path, probes=_probes({"x86_64", "aarch64"}))
    with pytest.raises(CapabilityError) as exc:
        s._resolve_arch("auto")
    assert exc.value.code == "isf.arch_undetected"
    assert any("several arches" in w for w in s.warnings)


def test_resolve_arch_nothing_verifies_never_defaults(tmp_path):
    s = _bare_session(tmp_path, probes=_probes(set()))
    with pytest.raises(CapabilityError) as exc:
        s._resolve_arch("auto")
    assert exc.value.code == "isf.arch_undetected"


def test_paging_self_test_unverified_root_and_exceptions_do_not_count(tmp_path):
    def find_root(dump, arch, vmcoreinfo=None):
        if arch == "x86_64":
            raise RuntimeError("cannot walk")
        return SimpleNamespace(verified=False)
    s = _bare_session(tmp_path, probes=SimpleNamespace(resolve_arch=lambda n: n,
                                                       find_page_table_root=find_root))
    assert s._arch_from_paging_self_test() is None


def test_probe_uses_the_drafts_arch_when_auto(monkeypatch, tmp_path):
    pytest.importorskip("pakunoda")
    seen = []

    class Recording(FakeSession):
        def __init__(self, image, arch, params):
            seen.append(arch)
            super().__init__(image, arch, params)

    monkeypatch.setattr(T, "_Session", Recording)
    image = tmp_path / "img.lime"
    image.write_bytes(b"x")
    case_dir = str(tmp_path / "case")
    Recording.capture = T.file_sha256(image)
    T.isf_draft_create_result(case_dir, Recording.capture, "d", "aarch64")
    T.isf_probe_result(str(image), "kallsyms", case_dir=case_dir, draft="d")
    T.isf_probe_result(str(image), "kallsyms", arch="x86_64", case_dir=case_dir, draft="d")
    T.isf_probe_result(str(image), "kallsyms")
    assert seen == ["aarch64", "x86_64", "auto"]


# -- gated real image --------------------------------------------------------------

CORPUS = os.environ.get("MEMDIVER_IMAGE_CORPUS")
ARISTA = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"
needs_corpus = pytest.mark.skipif(
    not CORPUS or not (Path(CORPUS) / f"{ARISTA}.lime").is_file(),
    reason="MEMDIVER_IMAGE_CORPUS must point at pakunoda/experiments/dumps/acquired")


@needs_corpus
def test_arista_end_to_end(tmp_path):
    pytest.importorskip("pakunoda")
    image = str(Path(CORPUS) / f"{ARISTA}.lime")
    shipped = str(Path(CORPUS) / f"{ARISTA}.isf.json")
    case_dir = str(tmp_path / "case")
    capture = T._capture(image)
    T.isf_draft_create_result(case_dir, capture, "arista", "x86_64")

    ks = payload(T.isf_probe_result(image, "kallsyms", case_dir=case_dir, draft="arista"))
    assert ks["arch_source"] and ks["imported"]["symbols"] >= 100_000 and ks["truncated"]

    pt = payload(T.isf_probe_result(image, "page_table_root"))["rows"][0]
    assert pt["pgd_phys"] == 0x2A0C000 and pt["levels"] == 4 and pt["verified"]

    legs = payload(T.isf_probe_result(image, "layout_legs", case_dir=case_dir, draft="arista",
                                      params={"type_hints_isf": shipped}))
    assert legs["imported"]["claims"] >= 100
    print("legs", legs["counts"], legs["timings"], legs["init_task"]["disagreement"])

    diff = payload(T.isf_draft_diff_result(case_dir, capture, "arista", against_isf=shipped,
                                           only={"user_types": ["task_struct"]}))
    changed = [item for item in diff["items"] if item["change"] == "changed"]
    # Fields: zero changed. The one struct-level change is the honest size placeholder
    # (no size claim for task_struct, so the draft says size 0 / size_unknown).
    assert not [c for c in changed if c["key"][0] == "field"]
    assert all(c["after"] == {"kind": "struct", "size": 0} for c in changed)


# -- review-fix regressions ------------------------------------------------------

def _void_claims():
    tier = SimpleNamespace(value="exact")
    return [SimpleNamespace(struct="task", member="pid", offset=8, width=4, tier=tier,
                            source="leg", evidence=("e",), witnesses=1)]


def test_void_placeholder_never_beats_donor_hint(case, tmp_path):
    store = T._store(case)
    store.import_layout_claims(CAP, "d", _void_claims(), type_hints={})   # untyped -> void
    donor_isf = json.loads(Path(donor(tmp_path)).read_text())
    hints = T._hint_types(store, CAP, "d", donor_isf)
    assert hints[("task", "pid")] == INT
    assert ("task", "pid") not in T._hint_types(store, CAP, "d", None)


def test_real_draft_type_still_beats_donor(case, tmp_path):
    store = T._store(case)
    other = {"kind": "base", "name": "long"}
    T.isf_draft_set_result(case, CAP, "d", "struct", {"name": "task", "size": 64})
    T.isf_draft_set_result(case, CAP, "d", "field",
                           {"struct": "task", "field": "pid", "offset": 8, "type": other})
    donor_isf = json.loads(Path(donor(tmp_path)).read_text())
    assert T._hint_types(store, CAP, "d", donor_isf)[("task", "pid")] == other


def test_diff_symbol_addresses_are_hex_strings(case):
    big = 0xFFFFFFFF82000000
    T.isf_draft_set_result(case, CAP, "d", "symbol", {"name": "init_task", "address": big})
    out = payload(T.isf_draft_diff_result(case, CAP, "d", against_isf=_empty_isf(case)))
    item = [i for i in out["items"] if i["key"][0] == "symbol"][0]
    assert item["after"]["address"] == hex(big)


def _empty_isf(case):
    path = Path(case) / "empty.isf.json"
    path.write_text(json.dumps({"base_types": {}, "user_types": {}, "enums": {},
                                "symbols": {}}))
    return str(path)


def test_init_task_va_is_hex(fake):
    class Big(FakeSession):
        def init_task(self):
            return {"va": 0xFFFFFFFF82000000, "phys": 100, "source": "kallsyms",
                    "probe": {"va": 0xFFFFFFFF82000010, "phys": 2}, "disagreement": None}
    T._Session = Big
    row = payload(T.isf_probe_result(fake, "init_task"))["rows"][0]
    assert row["va"] == "0xffffffff82000000" and row["probe"]["va"] == "0xffffffff82000010"


def test_session_closes_dump_when_arch_unsupported(monkeypatch, tmp_path):
    pytest.importorskip("pakunoda")
    from pakunoda import probes
    closed = []
    dump = SimpleNamespace(close=lambda: closed.append(1))
    monkeypatch.setattr(probes, "open_dump", lambda image: dump)
    monkeypatch.setattr(T, "file_sha256", lambda p: "a" * 64)
    image = tmp_path / "i.lime"
    image.write_bytes(b"x")
    with pytest.raises(CapabilityError) as e:
        T._Session(image, "no-such-arch", {})
    assert closed == [1] and e.value.category.name == "UNSUPPORTED"


def _seed_symbols(case, names):
    for i, n in enumerate(names):
        T.isf_draft_set_result(case, CAP, "d", "symbol", {"name": n, "address": i})


def test_get_search_is_case_insensitive_over_names(case):
    _seed_symbols(case, ["Init_Task", "swapper", "do_init", "zzz"])
    sec = payload(T.isf_draft_get_result(case, CAP, "d", only={"symbols": []},
                                         search="INIT"))["sections"]["symbols"]
    assert sorted(sec["items"]) == ["Init_Task", "do_init"]
    assert sec["total"] == 2 and not sec["truncated"]


def test_get_offset_paging_total_and_truncated(case):
    _seed_symbols(case, [f"s{i}" for i in range(5)])
    pages = []
    for off in (0, 2, 4):
        got = payload(T.isf_draft_get_result(case, CAP, "d", only={"symbols": []},
                                             limit=2, offset=off))
        sec = got["sections"]["symbols"]
        pages.append((list(sec["items"]), sec["total"], sec["offset"], sec["limit"],
                      sec["truncated"], got["truncated"]))
    assert pages == [(["s0", "s1"], 5, 0, 2, True, True), (["s2", "s3"], 5, 2, 2, True, True),
                     (["s4"], 5, 4, 2, False, False)]


def test_get_validates_offset_and_limit(case):
    for kw, code in (({"offset": -1}, "isf_offset_invalid"), ({"limit": 0}, "isf_limit_invalid")):
        with pytest.raises(CapabilityError) as exc:
            T.isf_draft_get_result(case, CAP, "d", only={"symbols": []}, **kw)
        assert exc.value.code == code


def test_get_field_origins_and_untyped_flag(case):
    T.isf_draft_set_result(case, CAP, "d", "struct", {"name": "task", "size": 64})
    T.isf_draft_set_result(case, CAP, "d", "field",
                           {"struct": "task", "field": "pid", "offset": 8, "type": INT})
    T.isf_draft_set_result(case, CAP, "d", "field",
                           {"struct": "task", "field": "signal", "offset": 16, "type": INT},
                           evidence=["type_unknown"])
    T.isf_draft_set_result(case, CAP, "d", "base_type", {
        "name": "int", "size": 4, "signed": True, "kind": "int", "endian": "little"})
    got = payload(T.isf_draft_get_result(
        case, CAP, "d", only={"user_types": [], "base_types": []}, include_origins=True))
    ut = got["sections"]["user_types"]
    assert ut["items"]["task"]["untyped_fields"] == 1
    fo = ut["field_origins"]
    assert fo["task.pid"]["untyped"] is False and fo["task.signal"]["untyped"] is True
    assert fo["task.pid"]["created"] and fo["task.pid"]["entry_id"]
    assert set(fo["task.pid"]["provenance"]) == {"source", "tier", "evidence", "author",
                                                 "witnesses"}
    assert got["sections"]["base_types"]["origins"]["int"]["op"]
