"""Capture v2b sibling groups in tools/vol3_capture (host-testable parts).

``sibling_frames.py``: pagemap / kpageflags / maps / smaps_rollup / stat / net-tcp / ELF
build-id parsing on fixture bytes, the per-run secret scan against a fake ``/proc/<pid>/mem``,
and connection discovery against a fixture process table. ``gt_json.py``: the per-connection
SSH ground truth, the sibling plan, ``siblings[]`` records and ``keys[]`` entries.
"""

from __future__ import annotations

import importlib.util
import json
import py_compile
import re
import struct
from pathlib import Path

import pytest

CAPTURE_DIR = Path(__file__).resolve().parents[1] / "tools" / "vol3_capture"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_vol3_capture_sib_{name}",
                                                  CAPTURE_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sf = _load("sibling_frames")
gt_json = _load("gt_json")

PAGE = 4096

# --- pagemap / kpageflags -------------------------------------------------------------------


def test_decode_pagemap_present_exclusive_entry():
    entry = (1 << 63) | (1 << 56) | (1 << 55) | 0xD0724
    flags = sf.decode_pagemap_entry(entry)
    assert flags["present"] == 1 and flags["exclusive"] == 1 and flags["soft_dirty"] == 1
    assert flags["swapped"] == 0 and flags["file_or_shared_anon"] == 0
    assert flags["pfn"] == 0xD0724 and flags["raw"] == f"0x{entry:016x}"


def test_decode_pagemap_file_page_keeps_pfn_bits_0_to_54():
    entry = (1 << 63) | (1 << 61) | ((1 << 55) - 1)
    flags = sf.decode_pagemap_entry(entry)
    assert flags["file_or_shared_anon"] == 1 and flags["exclusive"] == 0
    assert flags["pfn"] == (1 << 55) - 1


def test_decode_pagemap_swapped_and_absent_have_no_pfn():
    assert sf.decode_pagemap_entry((1 << 62) | 0x1234)["pfn"] is None
    absent = sf.decode_pagemap_entry(0)
    assert absent["present"] == 0 and absent["pfn"] is None


def test_unpack_u64s_little_endian_fixture_bytes():
    raw = struct.pack("<3Q", 1, 1 << 63, 0xDEADBEEF) + b"\x01\x02"   # trailing partial entry
    assert sf.unpack_u64s(raw) == [1, 1 << 63, 0xDEADBEEF]


def test_decode_kpageflags_named_and_kernel_internal_bits():
    # REFERENCED UPTODATE DIRTY LRU MMAP ANON SWAPBACKED + MAPPEDTODISK (bit 34)
    flags = 0x40000583C
    assert sf.decode_kpageflags(flags) == [
        "REFERENCED", "UPTODATE", "DIRTY", "LRU", "MMAP", "ANON", "SWAPBACKED", "MAPPEDTODISK"]
    assert sf.decode_kpageflags(1 << 24) == ["ZERO_PAGE"]
    assert sf.decode_kpageflags(0) == []


# --- maps / smaps_rollup / stat / net tcp ---------------------------------------------------

MAPS = """\
5603c9a00000-5603c9a2c000 r--p 00000000 fd:01 1835123                    /usr/sbin/dropbear
5603c9c2c000-5603c9c2e000 rw-p 0002b000 fd:01 1835123                    /usr/sbin/dropbear
5603cb1f5000-5603cb216000 rw-p 00000000 00:00 0                          [heap]
7ffd1c3a1000-7ffd1c3c2000 rw-p 00000000 00:00 0                          [stack]
7ffd1c3f9000-7ffd1c3fd000 r--p 00000000 00:00 0                          [vvar]
7f0000000000-7f0000001000 rw-s 00000000 00:01 77                         /dev/zero (deleted)
7f0000002000-7f0000003000 rw-p 00000000 00:00 0
"""


def test_parse_maps_fields_and_rw_filter():
    maps = sf.parse_maps(MAPS)
    assert len(maps) == 7
    assert maps[0] == {"start": 0x5603C9A00000, "end": 0x5603C9A2C000, "perms": "r--p",
                       "offset": 0, "inode": 1835123, "path": "/usr/sbin/dropbear"}
    assert maps[-1]["path"] == ""
    rw = [m["path"] for m in maps if sf.rw_private_or_shared(m)]
    assert rw == ["/usr/sbin/dropbear", "[heap]", "[stack]", "/dev/zero (deleted)", ""]


SMAPS_ROLLUP = """\
5603c9a00000-ffffffffff601000 ---p 00000000 00:00 0                      [rollup]
Rss:                4120 kB
Pss:                1311 kB
Shared_Clean:       2900 kB
Private_Dirty:       812 kB
Swap:                  0 kB
"""


def test_parse_smaps_rollup():
    parsed = sf.parse_smaps_rollup(SMAPS_ROLLUP)
    assert parsed["range"] == "5603c9a00000-ffffffffff601000"
    assert parsed["Rss"] == 4120 and parsed["Private_Dirty"] == 812 and parsed["Swap"] == 0


def test_parse_stat_comm_with_spaces_and_parens():
    fields = " ".join(["S", "988"] + ["0"] * 17 + ["123456"] + ["0"] * 20)
    parsed = sf.parse_stat(f"1001 (sshd: a) (b)) {fields}")
    assert parsed == {"comm": "sshd: a) (b)", "state": "S", "ppid": 988,
                      "starttime_ticks": 123456}


NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:07E7 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4101 1
   1: 0100007F:07E7 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000     0        0 4207 1
   2: 0100007F:A1B2 0100007F:07E7 01 00000000:00000000 00:00000000 00000000     0        0 4206 1
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3000 1
"""


def test_parse_proc_net_tcp_skips_both_headers():
    rows = sf.parse_proc_net_tcp(NET_TCP)
    assert len(rows) == 4
    assert rows[1] == {"local_port": 2023, "remote_port": 0xA1B2, "state": "01", "inode": 4207}
    assert rows[3]["local_port"] == 22
    assert sf.server_inode(rows, 2023, 0xA1B2) == 4207
    assert sf.server_inode(rows, 2023, 1) is None


# --- ELF build-id -------------------------------------------------------------------------


def _note(name: bytes, ntype: int, desc: bytes) -> bytes:
    pad = lambda b: b + b"\0" * (-len(b) % 4)   # noqa: E731
    return struct.pack("<III", len(name), len(desc), ntype) + pad(name) + pad(desc)


def _elf64(notes: list[bytes]) -> bytes:
    phoff, phnum = 64, len(notes)
    body_off = phoff + 56 * phnum
    header = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, phoff, 0, 0, 64, 56, phnum, 0, 0, 0)
    phdrs, blobs, off = b"", b"", body_off
    for note in notes:
        phdrs += struct.pack("<IIQQQQQQ", 4, 4, off, 0, 0, len(note), len(note), 4)
        blobs += note
        off += len(note)
    return header + phdrs + blobs


def test_elf_build_id_prefers_gnu_note():
    build_id = bytes(range(20))
    data = _elf64([_note(b"Go\0", 4, b"go-id/xyz"), _note(b"GNU\0", 3, build_id)])
    assert sf.elf_build_id(data) == ("gnu", build_id.hex())


def test_elf_build_id_go_fallback_and_non_elf():
    assert sf.elf_build_id(_elf64([_note(b"Go\0", 4, b"abc/def")])) == ("go", "abc/def")
    assert sf.elf_build_id(_elf64([])) == (None, None)
    assert sf.elf_build_id(b"#!/bin/sh\n") == (None, None)


# --- scan --------------------------------------------------------------------------------


def test_find_all_overlapping_and_present_runs():
    assert sf.find_all(b"aaaa", b"aa") == [0, 1, 2]
    present = 1 << 63
    entries = [present, present, 0, present, (1 << 62) | present, present]
    assert sf.present_runs(0x1000, entries) == [
        (0x1000, 0x3000), (0x4000, 0x5000), (0x6000, 0x7000)]


class FakeMem:
    """Sparse stand-in for /proc/<pid>/mem: {va: bytes}."""

    def __init__(self, regions: dict):
        self.regions, self.pos = regions, 0

    def seek(self, pos):
        self.pos = pos

    def read(self, length):
        for start, data in self.regions.items():
            if start <= self.pos < start + len(data):
                off = self.pos - start
                return data[off:off + length]
        return b""


@pytest.fixture
def no_kpage(monkeypatch):
    calls = []

    def fake(path, index):
        calls.append((path, index))
        return 2 if path.endswith("kpagecount") else 0x5838

    monkeypatch.setattr(sf, "_read_u64_at", fake)
    return calls


def test_scan_run_finds_page_straddling_secret_on_both_frames(no_kpage):
    secret = bytes(range(1, 33))
    base = 0x7F0000000000
    data = bytearray(3 * PAGE)
    data[PAGE - 10:PAGE + 22] = secret          # crosses page 0 -> page 1
    data[2 * PAGE + 100:2 * PAGE + 132] = secret
    entries = [(1 << 63) | (1 << 56) | 0x100, (1 << 63) | 0x200, (1 << 63) | (1 << 56) | 0x300]
    frames, stats = [], {"present_bytes_scanned": 0, "errors": []}
    sf._scan_run(FakeMem({base: bytes(data)}), base, base + 3 * PAGE, 31, {"K": secret},
                 entries, base, frames, stats)
    assert [(f["page_va"], f["pfn"]) for f in frames] == [
        (f"0x{base:x}", 0x100), (f"0x{base + PAGE:x}", 0x200), (f"0x{base + 2 * PAGE:x}", 0x300)]
    assert frames[0]["va"] == frames[0]["occurrence_va"] == f"0x{base + PAGE - 10:x}"
    assert frames[1]["va"] == f"0x{base + PAGE:x}"            # continuation starts at its page
    assert frames[1]["occurrence_va"] == frames[0]["occurrence_va"]
    assert frames[0]["pagemap_flags"]["exclusive"] == 1 and frames[1]["pagemap_flags"]["exclusive"] == 0
    assert frames[0]["kpagecount"] == 2 and frames[0]["kpageflags"] == "0x5838"
    assert "ANON" in frames[0]["kpageflags_names"]
    summary = sf.summarize_frames(frames)
    assert summary == {"frames": 3, "distinct_pfns": 3, "present": 3, "exclusive": 2,
                       "shared_kpagecount_gt1": 3, "secrets_found": ["K"]}


def test_scan_run_chunk_overlap_does_not_double_count(monkeypatch, no_kpage):
    monkeypatch.setattr(sf, "SCAN_CHUNK", PAGE)
    secret = b"\xaa" * 7 + b"\xbb" * 9
    base = 0x10000
    data = bytearray(2 * PAGE)
    data[PAGE - 4:PAGE + 12] = secret           # inside chunk 0's overlap window
    entries = [(1 << 63) | 1, (1 << 63) | 2]
    frames, stats = [], {"present_bytes_scanned": 0, "errors": []}
    sf._scan_run(FakeMem({base: bytes(data)}), base, base + 2 * PAGE, len(secret) - 1,
                 {"s": secret}, entries, base, frames, stats)
    assert len(frames) == 2 and len({f["occurrence_va"] for f in frames}) == 1


# --- discovery ----------------------------------------------------------------------------

TABLE = {
    973: {"ppid": 1}, 988: {"ppid": 973}, 1001: {"ppid": 988},
    927: {"ppid": 1}, 940: {"ppid": 927}, 5000: {"ppid": 4999}, 4999: {"ppid": 1},
}


def test_chain_below_listener():
    assert sf.chain_below(1001, 973, TABLE) == [988, 1001]
    assert sf.chain_below(940, 927, TABLE) == [940]
    assert sf.chain_below(5000, 973, TABLE) == []


def test_ssh_roles():
    assert sf.ssh_roles("openssh", 2) == ["monitor", "session"]
    assert sf.ssh_roles("dropbear", 1) == ["session"]


def test_discover_connection_openssh_monitor_and_session(monkeypatch):
    rows = [{"local_port": 2201, "remote_port": 40000, "state": "01", "inode": 77}]
    monkeypatch.setattr(sf, "socket_holders", lambda inode: [988, 1001, 984] if inode == 77 else [])
    group = {"group": "openssh", "listener_pid": 973, "server_port": 2201}
    conn = {"conn_id": "openssh-1", "client_port": 40000, "client_pid": 984}
    assert sf.discover_connection(group, conn, rows, TABLE) == [
        {"pid": 988, "role": "monitor", "conn_id": "openssh-1"},
        {"pid": 1001, "role": "session", "conn_id": "openssh-1"}]


def test_discover_connection_errors(monkeypatch):
    group = {"group": "dropbear", "listener_pid": 927, "server_port": 2023}
    conn = {"conn_id": "dropbear-1", "client_port": 1}
    with pytest.raises(RuntimeError, match="no established"):
        sf.discover_connection(group, conn, [], TABLE)
    monkeypatch.setattr(sf, "socket_holders", lambda inode: [5000])
    rows = [{"local_port": 2023, "remote_port": 1, "state": "01", "inode": 9}]
    with pytest.raises(RuntimeError, match="not below listener"):
        sf.discover_connection(group, conn, rows, TABLE)


def test_member_secrets_by_conn_id():
    group = {"connections": [{"conn_id": "a", "secrets": {"K": "00" * 32}}]}
    assert sf.member_secrets(group, {"conn_id": "a"}) == {"K": "00" * 32}
    assert sf.member_secrets(group, {"conn_id": None}) == {}


# --- gt_json ------------------------------------------------------------------------------

K_INT = "eb4cd633443279fba5cf157aced2e3f896cdb9c41827bc2327ab98f2bcd2e819"
H = "589bc2c926793af8a8047c7fca834e606f56cb913a41e022748df954ae30b9f2"
KEYS = {"A": "11" * 16, "B": "22" * 16, "C": "33" * 32, "D": "44" * 32,
        "E": "55" * 32, "F": "66" * 32}


def _client_events(conn_id="dropbear-1", group="dropbear", h=H, k_int=K_INT, port=40001):
    out = [{"event": "compute_key", "letter": letter, "key_hex": KEYS[letter],
            "K_int_hex": k_int, "K_mpint_hex": "00000021" + "00" + k_int, "H_hex": h,
            "session_id_hex": H, "hash": "sha256",
            "agreed": {"Kex": {"local": "curve25519-sha256@libssh.org"}}}
           for letter in "ACEBDF"]
    out.append({"event": "connected", "group": group, "conn_id": conn_id, "client_pid": 900,
                "client_port": port, "server_port": 2023, "cipher_c2s": "aes256-ctr",
                "cipher_s2c": "aes256-ctr", "mac_c2s": "hmac-sha2-256",
                "mac_s2c": "hmac-sha2-256", "remote_version": "SSH-2.0-dropbear_2022.83",
                "paramiko_version": "2.12.0"})
    return out


def test_ssh_session_gt_per_direction_keys():
    gt = gt_json.ssh_session_gt(_client_events())
    assert gt["K_int_hex"] == K_INT and gt["H_hex"] == gt["session_id_hex"] == H
    assert gt["kex"] == "curve25519-sha256@libssh.org" and gt["client_port"] == 40001
    assert gt["session_keys"]["c2s"] == {"cipher": "aes256-ctr", "mac": "hmac-sha2-256",
                                         "iv_hex": KEYS["A"], "enc_key_hex": KEYS["C"],
                                         "mac_key_hex": KEYS["E"]}
    assert gt["session_keys"]["s2c"]["enc_key_hex"] == KEYS["D"]
    assert gt["session_keys"]["s2c"]["mac_key_hex"] == KEYS["F"]
    assert list(gt["keys"]) == list("ABCDEF") and gt["rekeyed"] is False


def test_ssh_session_gt_latest_kex_and_requires_one():
    gt = gt_json.ssh_session_gt(_client_events() + _client_events(h="ab" * 32, k_int="01" * 32))
    assert gt["H_hex"] == "ab" * 32 and gt["rekeyed"] is True
    with pytest.raises(ValueError):
        gt_json.ssh_session_gt([{"event": "connected"}])


def test_ssh_frame_secrets_pads_k():
    gt = gt_json.ssh_session_gt(_client_events(k_int="ff" * 31))
    secrets = gt_json.ssh_frame_secrets(gt)
    assert secrets["K"] == "00" + "ff" * 31
    assert secrets["enc_c2s"] == KEYS["C"] and secrets["iv_s2c"] == KEYS["B"]
    assert set(secrets) == {"K", "iv_c2s", "iv_s2c", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c"}


def _write_sibdir(tmp_path: Path) -> Path:
    sib = tmp_path / "sib"
    sib.mkdir()
    (sib / "group_dropbear.json").write_text(json.dumps(
        {"group": "dropbear", "expected_shape": "forked", "listener_pid": 927,
         "server_port": 2023}))
    (sib / "group_gocryptfs.json").write_text(json.dumps(
        {"group": "gocryptfs", "expected_shape": "independent"}))
    for i in (2, 1):
        (sib / f"events_dropbear-{i}.jsonl").write_text("\n".join(
            json.dumps(e) for e in _client_events(f"dropbear-{i}", port=40000 + i)) + "\n")
    for i, pid in ((1, 1089), (2, 1132)):
        (sib / f"mount_gocryptfs-{i}.json").write_text(json.dumps(
            {"group": "gocryptfs", "conn_id": f"gocryptfs-{i}", "mountpoint": f"/mnt/m{i}",
             "cipher_dir": f"/c{i}", "master_key_hex": f"{i:02x}" * 32, "cipher": "aes-256-gcm",
             "daemon_pid": pid}))
    return sib


def test_sibling_plan_groups_connections_and_daemons(tmp_path):
    plan = gt_json.sibling_plan(str(_write_sibdir(tmp_path)))
    groups = {g["group"]: g for g in plan["groups"]}
    drop = groups["dropbear"]
    assert drop["listener_pid"] == 927 and drop["expected_shape"] == "forked"
    assert [c["conn_id"] for c in drop["connections"]] == ["dropbear-1", "dropbear-2"]
    assert drop["connections"][1]["client_port"] == 40002
    assert drop["connections"][0]["secrets"]["enc_c2s"] == KEYS["C"]
    goc = groups["gocryptfs"]
    assert [m["pid"] for m in goc["members"]] == [1089, 1132]
    assert all(m["role"] == "daemon" for m in goc["members"])
    assert all(c["gt"]["own_process"] is True for c in goc["connections"])
    assert goc["connections"][1]["secrets"] == {"master_key": "02" * 32}


def test_sibling_plan_flags_shared_daemon(tmp_path):
    sib = _write_sibdir(tmp_path)
    mount = json.loads((sib / "mount_gocryptfs-2.json").read_text())
    mount["daemon_pid"] = 1089
    (sib / "mount_gocryptfs-2.json").write_text(json.dumps(mount))
    goc = {g["group"]: g for g in gt_json.sibling_plan(str(sib))["groups"]}["gocryptfs"]
    assert [c["gt"]["own_process"] for c in goc["connections"]] == [False, False]


def test_cmd_siblings_records_keys_and_finalize(tmp_path):
    sib = _write_sibdir(tmp_path)
    plan_path = tmp_path / "plan.json"
    gt_json.cmd_sibling_plan(str(sib), str(plan_path))
    collected = {"members": [
        {"group": "dropbear", "expected_shape": "forked", "pid": 927, "role": "listener",
         "conn_id": None, "frames": []},
        {"group": "dropbear", "expected_shape": "forked", "pid": 940, "role": "session",
         "conn_id": "dropbear-1", "frames": [{"pfn": 5}]},
        {"group": "gocryptfs", "expected_shape": "independent", "pid": 1089, "role": "daemon",
         "conn_id": "gocryptfs-1", "frames": []},
    ]}
    collected_path = tmp_path / "collected.json"
    collected_path.write_text(json.dumps(collected))
    frags, out = tmp_path / "frags.jsonl", tmp_path / "secrets.json"
    gt_json.cmd_siblings(str(frags), str(plan_path), str(collected_path))
    gt_json.cmd_finalize(str(frags), str(out), "x86_64")
    doc = json.loads(out.read_text())
    sibs = doc["siblings"]
    assert [m["pid"] for m in sibs] == [927, 940, 1089]
    assert "ssh" not in sibs[0] and "gocryptfs" not in sibs[0]
    assert sibs[1]["ssh"]["session_keys"]["c2s"]["enc_key_hex"] == KEYS["C"]
    assert sibs[2]["gocryptfs"]["master_key_hex"] == "01" * 32
    keys = {k["id"]: k for k in doc["keys"]}
    assert keys["siblings.dropbear-1.enc_c2s"]["kind"] == "sibling-dropbear-enc_c2s"
    assert keys["siblings.gocryptfs-2.master_key"]["source"] == "siblings:gocryptfs:gocryptfs-2"
    assert len(keys) == 2 * 7 + 2


def test_finalize_without_siblings_has_no_section(tmp_path):
    out = tmp_path / "secrets.json"
    gt_json.cmd_finalize(str(tmp_path / "none.jsonl"), str(out), "x86_64")
    assert "siblings" not in json.loads(out.read_text())


# --- stage script + client ----------------------------------------------------------------

STAGE = (CAPTURE_DIR / "secrets_stage.sh").read_text()


def _code_lines(text: str) -> list[str]:
    """Lines without comments (a trailing `  # ...` is dropped too)."""
    return [line.split("  #")[0] for line in text.splitlines()
            if not line.lstrip().startswith("#")]


def test_stage_siblings_is_opt_in():
    assert "SIBLINGS=0" in STAGE and "--siblings) SIBLINGS=1" in STAGE
    assert "if (( SIBLINGS )); then run_item siblings item_siblings; fi" in STAGE
    assert "if (( SIBLINGS )); then run_item siblings_frames item_siblings_frames; fi" in STAGE
    main = STAGE[STAGE.index("main() {"):]
    assert main.index("item_siblings_frames") > main.index("global_ground_truth")
    assert main.index("item_siblings_frames") < main.index("    finalize")


def test_stage_has_no_pipe_into_grep_q():
    offenders = [line for line in _code_lines(STAGE) if re.search(r"\|\s*grep\s+-q", line)]
    assert offenders == []


def test_stage_help_range_covers_header():
    lines = STAGE.splitlines()
    end = int(re.search(r"sed -n '2,(\d+)p'", STAGE).group(1))
    assert lines[end].startswith("# Idempotent") and "--siblings" in "\n".join(lines[:end])


def test_gt_ssh_client_compiles_and_reuses_tier_a_hooks(tmp_path):
    client = CAPTURE_DIR / "siblings" / "gt_ssh_client.py"
    py_compile.compile(str(client), cfile=str(tmp_path / "c.pyc"), doraise=True)
    src = client.read_text()
    assert '"..", "ssh_tier_a"' in src and "gt_server.install_hooks()" in src
    assert (CAPTURE_DIR / "ssh_tier_a" / "gt_server.py").is_file()
