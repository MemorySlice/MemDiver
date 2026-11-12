#!/usr/bin/env python3
"""Sibling-group ground truth: process identity + PFN frames (runs IN the guest, root).

Used by secrets_stage.sh's ``siblings`` item (capture v2b). Two subcommands:

  discover PLAN_JSON
        Fill in the server-side processes of every planted connection. PLAN_JSON
        holds ``{"groups": [...]}``; each SSH group names its ``listener_pid`` and
        ``server_port`` and lists ``connections`` with the client's local port.
        A connection's server processes are the holders of the socket whose
        local port is the server port and whose remote port is the client's
        port, walked up to the direct child of the listener. The plan is
        rewritten in place with ``members`` per group.

  collect PLAN_JSON OUT_JSON
        For every member: comm, exe, ELF build-id, ppid, start time, smaps_rollup
        and ``frames[]`` -- one entry per (secret occurrence, page) found by
        scanning the member's own present rw pages via /proc/<pid>/mem. Each
        frame carries the /proc/<pid>/pagemap entry (PFN bits 0-54, 55 soft-dirty,
        56 exclusively-mapped, 61 file-page/shared-anon, 62 swapped, 63 present)
        and /proc/kpagecount + /proc/kpageflags for its PFN. Only pages already
        present are read, so the scan faults nothing in.

Python 3 standard library only.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time

PAGE = 4096
PFN_MASK = (1 << 55) - 1
PM_SOFT_DIRTY = 1 << 55
PM_EXCLUSIVE = 1 << 56
PM_FILE_SHARED = 1 << 61
PM_SWAPPED = 1 << 62
PM_PRESENT = 1 << 63
SCAN_CHUNK = 8 << 20
MIN_SECRET_BYTES = 8
# include/uapi/linux/kernel-page-flags.h
KPF_NAMES = (
    "LOCKED", "ERROR", "REFERENCED", "UPTODATE", "DIRTY", "LRU", "ACTIVE", "SLAB",
    "WRITEBACK", "RECLAIM", "BUDDY", "MMAP", "ANON", "SWAPCACHE", "SWAPBACKED",
    "COMPOUND_HEAD", "COMPOUND_TAIL", "HUGE", "UNEVICTABLE", "HWPOISON", "NOPAGE", "KSM",
    "THP", "OFFLINE", "ZERO_PAGE", "IDLE", "PGTABLE",
)
# fs/proc/page.c: kernel-internal bits 32+, exported to root only
KPF_HACKER_NAMES = {
    32: "RESERVED", 33: "MLOCKED", 34: "MAPPEDTODISK", 35: "PRIVATE", 36: "PRIVATE_2",
    37: "OWNER_PRIVATE", 38: "ARCH", 39: "UNCACHED", 40: "SOFTDIRTY", 41: "ARCH_2",
    42: "ARCH_3",
}
TCP_ESTABLISHED = "01"


# --- pure parsers (unit-tested on fixture bytes) -----------------------------------------

def decode_pagemap_entry(entry: int) -> dict:
    """One /proc/<pid>/pagemap u64 -> named fields (pfn None unless present, not swapped)."""
    present = bool(entry & PM_PRESENT)
    swapped = bool(entry & PM_SWAPPED)
    return {
        "raw": f"0x{entry:016x}",
        "present": int(present),
        "swapped": int(swapped),
        "file_or_shared_anon": int(bool(entry & PM_FILE_SHARED)),
        "exclusive": int(bool(entry & PM_EXCLUSIVE)),
        "soft_dirty": int(bool(entry & PM_SOFT_DIRTY)),
        "pfn": (entry & PFN_MASK) if present and not swapped else None,
    }


def unpack_u64s(data: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(data) // 8}Q", data[: len(data) // 8 * 8]))


def decode_kpageflags(flags: int) -> list[str]:
    names = [name for bit, name in enumerate(KPF_NAMES) if flags & (1 << bit)]
    return names + [name for bit, name in sorted(KPF_HACKER_NAMES.items()) if flags & (1 << bit)]


def parse_maps(text: str) -> list[dict]:
    """/proc/<pid>/maps lines -> [{start, end, perms, offset, inode, path}]."""
    out = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        start, end = (int(x, 16) for x in parts[0].split("-"))
        out.append({"start": start, "end": end, "perms": parts[1], "offset": int(parts[2], 16),
                    "inode": int(parts[4]), "path": parts[5].strip() if len(parts) > 5 else ""})
    return out


def rw_private_or_shared(mapping: dict) -> bool:
    """A readable+writable mapping that is not a special kernel area."""
    perms, path = mapping["perms"], mapping["path"]
    return perms[0] == "r" and perms[1] == "w" and path not in ("[vvar]", "[vsyscall]", "[vdso]")


def parse_smaps_rollup(text: str) -> dict:
    """``Key:   N kB`` lines -> {key: N}; the range header is kept as ``range``."""
    out: dict = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        fields = rest.split()
        if len(fields) == 2 and fields[1] == "kB" and fields[0].isdigit():
            out[key.strip()] = int(fields[0])
        elif "-" in key and " " in line and not out:
            out["range"] = line.split()[0]
    return out


def parse_stat(text: str) -> dict:
    """/proc/<pid>/stat -> {comm, state, ppid, starttime_ticks} (comm may hold spaces/parens)."""
    head, tail = text[: text.rindex(")")], text[text.rindex(")") + 2:]
    fields = tail.split()
    return {"comm": head[head.index("(") + 1:], "state": fields[0], "ppid": int(fields[1]),
            "starttime_ticks": int(fields[19])}


def parse_proc_net_tcp(text: str) -> list[dict]:
    """/proc/net/tcp{,6} text (header lines skipped) -> [{local_port, remote_port, state, inode}]."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 10 or not f[0].rstrip(":").isdigit():
            continue
        out.append({"local_port": int(f[1].rsplit(":", 1)[1], 16),
                    "remote_port": int(f[2].rsplit(":", 1)[1], 16),
                    "state": f[3], "inode": int(f[9])})
    return out


def _elf_notes(blob: bytes, little: bool) -> list[tuple[str, int, bytes]]:
    end = "<" if little else ">"
    notes, pos = [], 0
    while pos + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from(end + "III", blob, pos)
        pos += 12
        name = blob[pos:pos + namesz].rstrip(b"\0").decode("ascii", "replace")
        pos += (namesz + 3) & ~3
        desc = blob[pos:pos + descsz]
        pos += (descsz + 3) & ~3
        notes.append((name, ntype, desc))
    return notes


def elf_build_id(data: bytes) -> tuple[str | None, str | None]:
    """(kind, hex) from an ELF image's PT_NOTE segments: GNU build-id, else Go build-id."""
    if data[:4] != b"\x7fELF":
        return None, None
    is64, little = data[4] == 2, data[5] == 1
    end = "<" if little else ">"
    if is64:
        phoff, = struct.unpack_from(end + "Q", data, 0x20)
        phentsize, phnum = struct.unpack_from(end + "HH", data, 0x36)
    else:
        phoff, = struct.unpack_from(end + "I", data, 0x1C)
        phentsize, phnum = struct.unpack_from(end + "HH", data, 0x2A)
    found: dict = {}
    for i in range(phnum):
        base = phoff + i * phentsize
        ptype, = struct.unpack_from(end + "I", data, base)
        if ptype != 4:   # PT_NOTE
            continue
        if is64:
            off, = struct.unpack_from(end + "Q", data, base + 8)
            size, = struct.unpack_from(end + "Q", data, base + 32)
        else:
            off, = struct.unpack_from(end + "I", data, base + 4)
            size, = struct.unpack_from(end + "I", data, base + 16)
        for name, ntype, desc in _elf_notes(data[off:off + size], little):
            if name == "GNU" and ntype == 3:
                found.setdefault("gnu", desc.hex())
            elif name == "Go" and ntype == 4:
                found.setdefault("go", desc.decode("ascii", "replace"))
    for kind in ("gnu", "go"):
        if kind in found:
            return kind, found[kind]
    return None, None


def find_all(buf: bytes, needle: bytes) -> list[int]:
    out, pos = [], buf.find(needle)
    while pos != -1:
        out.append(pos)
        pos = buf.find(needle, pos + 1)
    return out


def present_runs(start: int, entries: list[int]) -> list[tuple[int, int]]:
    """Contiguous [va_start, va_end) runs of present, non-swapped pages."""
    runs: list[tuple[int, int]] = []
    for i, entry in enumerate(entries):
        if not (entry & PM_PRESENT) or entry & PM_SWAPPED:
            continue
        va = start + i * PAGE
        if runs and runs[-1][1] == va:
            runs[-1] = (runs[-1][0], va + PAGE)
        else:
            runs.append((va, va + PAGE))
    return runs


def summarize_frames(frames: list[dict]) -> dict:
    pfns = {f["pfn"] for f in frames if f.get("pfn") is not None}
    return {
        "frames": len(frames), "distinct_pfns": len(pfns),
        "present": sum(1 for f in frames if f["pagemap_flags"]["present"]),
        "exclusive": sum(1 for f in frames if f["pagemap_flags"]["exclusive"]),
        "shared_kpagecount_gt1": sum(1 for f in frames if (f.get("kpagecount") or 0) > 1),
        "secrets_found": sorted({f["secret"] for f in frames}),
    }


# --- /proc readers ------------------------------------------------------------------------

def _read(path: str, binary: bool = False):
    with open(path, "rb" if binary else "r") as fh:
        return fh.read()


def _read_u64_at(path: str, index: int) -> int | None:
    try:
        with open(path, "rb") as fh:
            fh.seek(index * 8)
            data = fh.read(8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else None
    except OSError:
        return None


def boot_time() -> float:
    for line in _read("/proc/stat").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return 0.0


def pagemap_entries(pid: int, start: int, end: int) -> list[int]:
    with open(f"/proc/{pid}/pagemap", "rb") as fh:
        fh.seek(start // PAGE * 8)
        return unpack_u64s(fh.read((end - start) // PAGE * 8))


def _frame(va: int, entry: int, secret: str) -> dict:
    flags = decode_pagemap_entry(entry)
    pfn = flags["pfn"]
    kflags = _read_u64_at("/proc/kpageflags", pfn) if pfn is not None else None
    return {
        "secret": secret, "va": f"0x{va:x}", "page_va": f"0x{va & ~(PAGE - 1):x}",
        "pfn": pfn, "pagemap_flags": flags,
        "kpagecount": _read_u64_at("/proc/kpagecount", pfn) if pfn is not None else None,
        "kpageflags": None if kflags is None else f"0x{kflags:x}",
        "kpageflags_names": None if kflags is None else decode_kpageflags(kflags),
    }


def scan_frames(pid: int, secrets: dict) -> tuple[list[dict], dict]:
    """Frames of every secret occurrence in PID's present rw pages, plus scan stats."""
    needles = {name: bytes.fromhex(h) for name, h in secrets.items()
               if h and len(h) // 2 >= MIN_SECRET_BYTES}
    frames: list[dict] = []
    stats = {"mappings_scanned": 0, "present_bytes_scanned": 0, "errors": []}
    if not needles:
        return frames, stats
    overlap = max(len(n) for n in needles.values()) - 1
    maps = [m for m in parse_maps(_read(f"/proc/{pid}/maps")) if rw_private_or_shared(m)]
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for mapping in maps:
            try:
                entries = pagemap_entries(pid, mapping["start"], mapping["end"])
            except OSError as exc:
                stats["errors"].append(f"pagemap {mapping['start']:x}: {exc}")
                continue
            stats["mappings_scanned"] += 1
            for run_start, run_end in present_runs(mapping["start"], entries):
                _scan_run(mem, run_start, run_end, overlap, needles, entries,
                          mapping["start"], frames, stats)
    return frames, stats


def _scan_run(mem, run_start, run_end, overlap, needles, entries, map_start, frames, stats):
    seen: set = set()
    pos = run_start
    while pos < run_end:
        length = min(SCAN_CHUNK + overlap, run_end - pos)
        try:
            mem.seek(pos)
            buf = mem.read(length)
        except OSError as exc:
            stats["errors"].append(f"mem {pos:x}: {exc}")
            buf = b""
        stats["present_bytes_scanned"] += min(SCAN_CHUNK, len(buf))
        for name, needle in needles.items():
            for off in find_all(buf, needle):
                va = pos + off
                if (name, va) in seen:
                    continue
                seen.add((name, va))
                for page_va in sorted({va & ~(PAGE - 1), (va + len(needle) - 1) & ~(PAGE - 1)}):
                    entry = entries[(page_va - map_start) // PAGE]
                    frame = _frame(max(va, page_va), entry, name)
                    frame["occurrence_va"] = f"0x{va:x}"
                    frames.append(frame)
        pos += SCAN_CHUNK


def proc_identity(pid: int, btime: float, clk_tck: int) -> dict:
    stat = parse_stat(_read(f"/proc/{pid}/stat"))
    exe = os.readlink(f"/proc/{pid}/exe")
    try:
        kind, build_id = elf_build_id(_read(f"/proc/{pid}/exe", binary=True))
    except (OSError, struct.error):
        kind, build_id = None, None
    cmdline = _read(f"/proc/{pid}/cmdline", binary=True).replace(b"\0", b" ").strip()
    return {
        "comm": stat["comm"], "exe": exe, "build_id": build_id, "build_id_kind": kind,
        "cmdline": cmdline.decode("utf-8", "replace"), "ppid": stat["ppid"],
        "start_time_ticks": stat["starttime_ticks"],
        "start_time": round(btime + stat["starttime_ticks"] / clk_tck, 2),
    }


# --- discover -----------------------------------------------------------------------------

def proc_table() -> dict:
    table = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                table[int(name)] = parse_stat(_read(f"/proc/{name}/stat"))
            except (OSError, ValueError):
                continue
    return table


def socket_holders(inode: int) -> list[int]:
    target, out = f"socket:[{inode}]", []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{name}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"/proc/{name}/fd/{fd}") == target:
                    out.append(int(name))
                    break
            except OSError:
                continue
    return sorted(out)


def chain_below(pid: int, top_parent: int, table: dict) -> list[int]:
    """[child-of-top_parent, ..., pid] following ppid links, or [] if not a descendant."""
    chain = [pid]
    while pid in table and table[pid]["ppid"] != top_parent:
        pid = table[pid]["ppid"]
        if pid <= 1:
            return []
        chain.append(pid)
    return list(reversed(chain)) if pid in table else []


def server_inode(tcp: list[dict], server_port: int, client_port: int) -> int | None:
    for row in tcp:
        if (row["local_port"], row["remote_port"]) == (server_port, client_port) \
                and row["state"] == TCP_ESTABLISHED and row["inode"]:
            return row["inode"]
    return None


def ssh_roles(group: str, depth: int) -> list[str]:
    """Role per process in the chain below the listener for one connection."""
    if group == "openssh":
        return ["monitor", "session", "child", "child"][:depth]
    return ["session"] + ["child"] * (depth - 1)


def discover_connection(group: dict, conn: dict, tcp: list[dict], table: dict) -> list[dict]:
    inode = server_inode(tcp, group["server_port"], conn["client_port"])
    if inode is None:
        raise RuntimeError(f"{conn['conn_id']}: no established server socket for client port "
                           f"{conn['client_port']}")
    chains = [chain_below(p, group["listener_pid"], table) for p in socket_holders(inode)
              if p != conn.get("client_pid")]
    chain = max((c for c in chains if c), key=len, default=[])
    if not chain:
        raise RuntimeError(f"{conn['conn_id']}: socket holders are not below listener "
                           f"{group['listener_pid']}")
    return [{"pid": pid, "role": role, "conn_id": conn["conn_id"]}
            for pid, role in zip(chain, ssh_roles(group["group"], len(chain)))]


def cmd_discover(plan_path: str) -> None:
    plan = json.loads(_read(plan_path))
    tcp_text = "".join(_read(p) for p in ("/proc/net/tcp", "/proc/net/tcp6") if os.path.exists(p))
    tcp, table = parse_proc_net_tcp(tcp_text), proc_table()
    for group in plan["groups"]:
        if "listener_pid" not in group:
            continue
        members = [{"pid": group["listener_pid"], "role": "listener", "conn_id": None}]
        for conn in group["connections"]:
            members += discover_connection(group, conn, tcp, table)
        group["members"] = members
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=2)
    print(json.dumps({g["group"]: [(m["pid"], m["role"]) for m in g.get("members", [])]
                      for g in plan["groups"]}))


# --- collect ------------------------------------------------------------------------------

def member_secrets(group: dict, member: dict) -> dict:
    conn = next((c for c in group.get("connections", [])
                 if c["conn_id"] == member.get("conn_id")), None)
    return dict(conn.get("secrets", {})) if conn else {}


def collect_member(group: dict, member: dict, btime: float, clk_tck: int) -> dict:
    pid = member["pid"]
    record = {"group": group["group"], "expected_shape": group["expected_shape"], **member}
    try:
        record.update(proc_identity(pid, btime, clk_tck))
        record["alive"] = True
    except OSError as exc:
        record.update(alive=False, error=str(exc))
        return record
    secrets = member_secrets(group, member)
    started = time.time()
    frames, stats = scan_frames(pid, secrets) if secrets else ([], {"note": "no member secret"})
    record["snapshot_time"] = round(time.time(), 3)
    record["frames"] = frames
    record["frames_scan"] = {**stats, "secrets_searched": sorted(secrets),
                             "seconds": round(time.time() - started, 3)}
    record["frames_summary"] = summarize_frames(frames)
    try:
        text = _read(f"/proc/{pid}/smaps_rollup")
        record["smaps_rollup"] = parse_smaps_rollup(text)
        record["smaps_rollup_text"] = text
    except OSError as exc:
        record["smaps_rollup"] = {"error": str(exc)}
    return record


def cmd_collect(plan_path: str, out_path: str) -> None:
    plan = json.loads(_read(plan_path))
    btime, clk_tck = boot_time(), os.sysconf("SC_CLK_TCK")
    members = []
    for group in plan["groups"]:
        for member in group.get("members", []):
            members.append(collect_member(group, member, btime, clk_tck))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"members": members, "snapshot_completed": round(time.time(), 3)}, fh)
    for m in members:
        s = m.get("frames_summary", {})
        print(f"{m['group']:9} {m.get('conn_id') or '-':11} {m['role']:8} pid={m['pid']:<6} "
              f"alive={m.get('alive')} frames={s.get('frames', 0)} excl={s.get('exclusive', 0)} "
              f"shared={s.get('shared_kpagecount_gt1', 0)}")


COMMANDS = {"discover": cmd_discover, "collect": cmd_collect}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    COMMANDS[sys.argv[1]](*sys.argv[2:])
