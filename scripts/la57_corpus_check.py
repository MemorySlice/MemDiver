#!/usr/bin/env python3
"""Measure ``linux.pslist`` over a corpus of x86_64 Linux memory images.

Purpose: compare Volatility 3 builds (for example a stock release against a
pull request that adds LA57 / 5-level paging support) on the same images, the
same ISFs and the same command line, one image at a time.

Corpus layout (one set of files per ``<stem>``)::

    <stem>.lime | <stem>.elf     the memory image (LiME / AVML / LEMON / ELF core)
    <stem>.isf.json              ISF symbols (and optionally <stem>.gt.isf.json)
    <stem>.meta.json             optional; ``architecture``, ``kernel_version``, ``la57``
    <stem>.ps_at_dump.txt        optional; ``ps`` output taken inside the guest
    <stem>.vol3_pslist.txt       optional; an earlier ``vol linux.pslist`` capture

Vol3 finds Linux ISFs through a symbols directory containing ``linux/<name>.json``.
For every image a private symbols directory is created under ``--work`` that holds
a single symlink to that image's ISF, so the multi-megabyte ISF is never copied and
vol3 never sees a second image's ISF.

Each ``--vol`` build gets its own ``--cache-path`` so one build's banner cache can
never leak into another build's run, and so the user's real vol3 cache is untouched.

Example::

    python scripts/la57_corpus_check.py \\
        --corpus /path/to/acquired --work /tmp/la57_work \\
        --vol stock=/path/to/venv-a/bin/vol --vol pr1991=/path/to/venv-b/bin/vol \\
        --out-json results.json --out-md results.md

The script is sequential on purpose: images are several GB each and the machine
is usually shared.  Results are appended to ``<work>/results.jsonl`` after every
run, so an interrupted run resumes where it stopped (``--resume``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

X86_64_NAMES = {"x86_64", "amd64"}
IMAGE_SUFFIXES = (".lime", ".elf", ".raw", ".mem")
VERSION_RE = re.compile(r"Volatility 3 Framework\s+(\S+)")
PSLIST_ROW_RE = re.compile(r"^0x[0-9a-fA-F]+\t(\d+)\t")
STDERR_TAIL_CHARS = 400


# --------------------------------------------------------------------------- #
# Corpus discovery
# --------------------------------------------------------------------------- #
def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _find_image(corpus: Path, stem: str) -> Optional[Path]:
    for suffix in IMAGE_SUFFIXES:
        candidate = corpus / f"{stem}{suffix}"
        if candidate.exists():
            return candidate
    return None


def _pick_isf(corpus: Path, stem: str, kind: str) -> Optional[Path]:
    """Return the ISF to use. ``gt`` = dwarf2json ground-truth ISF, ``plain`` = the other."""
    order = {
        "gt": ("gt.isf.json",),
        "plain": ("isf.json",),
        "auto": ("gt.isf.json", "isf.json"),
    }[kind]
    for ext in order:
        candidate = corpus / f"{stem}.{ext}"
        if candidate.exists():
            return candidate
    return None


def _la57_label(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def discover_images(
    corpus: Path, isf_kind: str, la57_ref: Dict[str, bool], only: Optional[Set[str]]
) -> List[Dict[str, Any]]:
    """Every x86_64 image that has an image file and an ISF, sorted by stem."""
    found: List[Dict[str, Any]] = []
    for meta_path in sorted(corpus.glob("*.meta.json")):
        stem = meta_path.name[: -len(".meta.json")]
        if only and stem not in only:
            continue
        meta = _load_json(meta_path)
        if str(meta.get("architecture", "")).lower() not in X86_64_NAMES:
            continue
        image, isf = _find_image(corpus, stem), _pick_isf(corpus, stem, isf_kind)
        if image is None or isf is None:
            continue
        found.append(
            {
                "stem": stem,
                "kernel": meta.get("kernel_version", "unknown"),
                "la57_meta": _la57_label(meta.get("la57")),
                "la57_ref": _la57_label(la57_ref.get(stem)),
                "image": image,
                "isf": isf,
                "ps_path": corpus / f"{stem}.ps_at_dump.txt",
                "pslist_txt": corpus / f"{stem}.vol3_pslist.txt",
            }
        )
    return found


# --------------------------------------------------------------------------- #
# Ground truth and output parsing
# --------------------------------------------------------------------------- #
def parse_ps_pids(path: Path) -> Optional[Set[int]]:
    """PIDs from a guest ``ps`` capture, or ``None`` if there is no usable file.

    Handles ``ps -ef`` / ``ps aux`` (PID column found from the header), BusyBox
    ``ps`` (PID first) and headerless ``pid ppid user comm cmd`` listings.
    """
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    column = _pid_column(lines)
    pids: Set[int] = set()
    for line in lines:
        parts = line.split()
        if len(parts) > column and parts[column].isdigit():
            pids.add(int(parts[column]))
    return pids or None


def _pid_column(lines: Iterable[str]) -> int:
    for line in lines:
        parts = line.split()
        if "PID" in parts:
            return parts.index("PID")
    return 0


def count_pslist_txt_rows(path: Path) -> Optional[int]:
    """Rows in an earlier ``vol linux.pslist`` text capture (header-only file = 0)."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    return sum(1 for line in text.splitlines() if PSLIST_ROW_RE.match(line))


def parse_pslist_json(stdout: str) -> Optional[List[int]]:
    """PIDs of every row in vol3's ``-r json`` output, or ``None`` if unparsable."""
    start = stdout.find("[")
    if start < 0:
        return None
    try:
        rows, _ = json.JSONDecoder().raw_decode(stdout[start:])
    except ValueError:
        return None
    pids: List[int] = []
    _collect_pids(rows, pids)
    return pids


def _collect_pids(rows: Any, out: List[int]) -> None:
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        pid = row.get("PID")
        if isinstance(pid, int):
            out.append(pid)
        _collect_pids(row.get("__children"), out)


# --------------------------------------------------------------------------- #
# Running vol3
# --------------------------------------------------------------------------- #
def _run_text(cmd: List[str]) -> str:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout + done.stderr


def _script_interpreter(script: str) -> Optional[str]:
    """Interpreter named by the shebang of a console-script wrapper."""
    try:
        with open(script, encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
    except OSError:
        return None
    return first[2:].strip() if first.startswith("#!") else None


def vol_version(vol: str) -> str:
    """Version of a vol3 build: from ``vol -h`` if it prints one, else from its Python package."""
    match = VERSION_RE.search(_run_text([vol, "-h"]))
    if match:
        return match.group(1)
    interpreter = _script_interpreter(vol)
    if interpreter:
        code = "from volatility3.framework import constants; print(constants.PACKAGE_VERSION)"
        lines = _run_text([interpreter, "-I", "-c", code]).strip().splitlines()
        if lines and re.fullmatch(r"\d+(\.\d+)+\S*", lines[-1]):
            return lines[-1]
    return "unknown"


def _force_symlink(target: Path, link: Path) -> Path:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target.resolve())
    return link


def prepare_image_dirs(work: Path, item: Dict[str, Any]) -> Tuple[Path, Path]:
    """Return (symbols dir holding only this image's ISF, space-free image symlink)."""
    stem = item["stem"]
    symbols = work / "symbols" / stem
    _force_symlink(item["isf"], symbols / "linux" / f"{stem}.json")
    image = _force_symlink(item["image"], work / "images" / f"{stem}{item['image'].suffix}")
    return symbols, image


def build_command(vol: str, cache: Path, symbols: Path, image: Path) -> List[str]:
    return [
        vol, "-q", "-r", "json", "--offline",
        "--cache-path", str(cache),
        "-s", str(symbols),
        "-f", str(image),
        "linux.pslist",
    ]  # fmt: skip


def _kill_group(proc: "subprocess.Popen[str]") -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_with_timeout(cmd: List[str], timeout: float) -> Tuple[Optional[int], str, str, bool]:
    """Run ``cmd``; on timeout kill its whole process group. Returns (rc, out, err, timed_out)."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        errors="replace", start_new_session=True,
    )  # fmt: skip
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, err = proc.communicate()
        return None, out or "", err or "", True


def _error_text(stderr: str) -> str:
    lines = [ln for ln in stderr.strip().splitlines() if ln.strip()]
    return " | ".join(lines[-3:])[-STDERR_TAIL_CHARS:]


def measure_one(
    label: str, vol: str, version: str, item: Dict[str, Any], work: Path, timeout: float
) -> Dict[str, Any]:
    symbols, image = prepare_image_dirs(work, item)
    cache = work / "cache" / label
    cache.mkdir(parents=True, exist_ok=True)
    cmd = build_command(vol, cache, symbols, image)
    started = time.monotonic()
    rc, out, err, timed_out = run_with_timeout(cmd, timeout)
    wall = time.monotonic() - started
    raw_dir = work / "raw" / label
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{item['stem']}.stdout.json").write_text(out)
    (raw_dir / f"{item['stem']}.stderr.txt").write_text(err)
    return summarize(label, version, item, cmd, rc, out, err, timed_out, wall, timeout)


def summarize(
    label: str, version: str, item: Dict[str, Any], cmd: List[str],
    rc: Optional[int], out: str, err: str, timed_out: bool, wall: float, timeout: float,
) -> Dict[str, Any]:  # fmt: skip
    pids = None if timed_out else parse_pslist_json(out)
    ps_pids = parse_ps_pids(item["ps_path"])
    record: Dict[str, Any] = {
        "label": label, "vol_version": version, "stem": item["stem"],
        "kernel": item["kernel"], "la57_meta": item["la57_meta"],
        "la57_ref": item["la57_ref"], "isf": item["isf"].name,
        "returncode": rc, "wall_s": round(wall, 1),
        "vol3_pslist_txt_rows": count_pslist_txt_rows(item["pslist_txt"]),
        "command": " ".join(cmd),
    }  # fmt: skip
    record.update(_pid_stats(pids, ps_pids))
    record["status"] = _status(timed_out, rc, pids)
    record["error"] = _error_for(record["status"], timeout, err)
    return record


def _pid_stats(pids: Optional[List[int]], ps_pids: Optional[Set[int]]) -> Dict[str, Any]:
    stats: Dict[str, Any] = {
        "rows": None, "distinct_pids": None, "ps_pids": len(ps_pids) if ps_pids else None,
        "overlap": None, "overlap_pct": None, "vol_only": None,
    }  # fmt: skip
    if pids is None:
        return stats
    distinct = set(pids)
    stats["rows"], stats["distinct_pids"] = len(pids), len(distinct)
    if ps_pids:
        common = distinct & ps_pids
        stats["overlap"] = len(common)
        stats["overlap_pct"] = round(100.0 * len(common) / len(ps_pids), 1)
        stats["vol_only"] = len(distinct - ps_pids)
    return stats


def _status(timed_out: bool, rc: Optional[int], pids: Optional[List[int]]) -> str:
    if timed_out:
        return "timeout"
    if rc != 0 or pids is None:
        return "error"
    return "zero_rows" if not pids else "ok"


def _error_for(status: str, timeout: float, stderr: str) -> str:
    if status == "timeout":
        return f"timeout after {timeout:.0f}s"
    if status == "error":
        return _error_text(stderr) or "no parsable JSON on stdout"
    return ""


# --------------------------------------------------------------------------- #
# Persistence and reporting
# --------------------------------------------------------------------------- #
def load_done(jsonl: Path) -> List[Dict[str, Any]]:
    if not jsonl.exists():
        return []
    records = []
    for line in jsonl.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def append_record(jsonl: Path, record: Dict[str, Any]) -> None:
    with open(jsonl, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _cell(record: Optional[Dict[str, Any]]) -> str:
    if record is None:
        return "-"
    if record["status"] in ("timeout", "error"):
        return record["status"].upper()
    text = f"{record['rows']}"
    if record["overlap_pct"] is not None:
        text += f" ({record['overlap']}/{record['ps_pids']}, {record['overlap_pct']}%)"
    return text


def render_markdown(records: List[Dict[str, Any]], labels: List[str]) -> str:
    by_key = {(r["label"], r["stem"]): r for r in records}
    stems = sorted({r["stem"] for r in records})
    versions = {r["label"]: r["vol_version"] for r in records}
    lines = ["## linux.pslist rows (and PIDs also present in ps_at_dump)", ""]
    header = ["image", "kernel", "LA57 meta", "LA57 ref", "acq. rows"]
    header += [f"{lb} ({versions.get(lb, '?')})" for lb in labels]
    lines += ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for stem in stems:
        first = next(r for r in records if r["stem"] == stem)
        row = [stem, first["kernel"], first["la57_meta"], first["la57_ref"],
               "-" if first["vol3_pslist_txt_rows"] is None else str(first["vol3_pslist_txt_rows"])]  # fmt: skip
        row += [_cell(by_key.get((lb, stem))) for lb in labels]
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "## Per-run detail", ""]
    lines += _detail_table(records)
    return "\n".join(lines) + "\n"


def _detail_table(records: List[Dict[str, Any]]) -> List[str]:
    cols = ["label", "image", "status", "rows", "distinct", "ps", "overlap", "pct", "vol_only", "wall_s", "error"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in sorted(records, key=lambda x: (x["stem"], x["label"])):
        vals = [r["label"], r["stem"], r["status"], r["rows"], r["distinct_pids"], r["ps_pids"],
                r["overlap"], r["overlap_pct"], r["vol_only"], r["wall_s"], r["error"]]  # fmt: skip
        out.append("| " + " | ".join("" if v is None else str(v).replace("|", "/") for v in vals) + " |")
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_vol_args(specs: List[str]) -> List[Tuple[str, str]]:
    parsed = []
    for spec in specs:
        label, sep, path = spec.partition("=")
        if not sep or not label or not path:
            raise SystemExit(f"--vol expects LABEL=PATH, got {spec!r}")
        parsed.append((label, path))
    labels = [lb for lb, _ in parsed]
    if len(set(labels)) != len(labels):
        raise SystemExit("--vol labels must be unique")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus", required=True, type=Path, help="directory with images, ISFs and metadata")
    p.add_argument("--work", required=True, type=Path, help="scratch dir for symlinks, caches and raw output")
    p.add_argument("--vol", action="append", default=[], metavar="LABEL=PATH",
                   help="a vol3 build to measure; repeat for several builds")  # fmt: skip
    p.add_argument("--timeout", type=float, default=900.0, help="seconds per image and build (default 900)")
    p.add_argument("--isf-kind", choices=("auto", "gt", "plain"), default="auto",
                   help="gt = <stem>.gt.isf.json (dwarf2json), plain = <stem>.isf.json, auto = gt first")  # fmt: skip
    p.add_argument("--la57-ref", type=Path, help="optional JSON {stem: bool} of an independent LA57 measurement")
    p.add_argument("--only", action="append", default=[], metavar="STEM", help="restrict to these stems")
    p.add_argument("--resume", action="store_true", help="skip (build, image) pairs already in <work>/results.jsonl")
    p.add_argument("--list", action="store_true", help="list the images that would be measured and exit")
    p.add_argument("--out-json", type=Path, help="write the final JSON report here")
    p.add_argument("--out-md", type=Path, help="write the markdown tables here")
    return p


def run_all(args: argparse.Namespace) -> List[Dict[str, Any]]:
    builds = parse_vol_args(args.vol)
    la57_ref = _load_json(args.la57_ref) if args.la57_ref else {}
    all_items = discover_images(args.corpus, args.isf_kind, la57_ref, None)
    items = [i for i in all_items if not args.only or i["stem"] in set(args.only)]
    if args.list:
        for item in items:
            print(f"{item['stem']}\t{item['image'].name}\t{item['isf'].name}")
        return []
    args.work.mkdir(parents=True, exist_ok=True)
    jsonl = args.work / "results.jsonl"
    done = load_done(jsonl) if args.resume else []
    seen = {(r["label"], r["stem"]) for r in done}
    records = list(done)
    versions = {label: vol_version(vol) for label, vol in builds}
    for index, item in enumerate(items):  # image-major: all builds on one image before the next
        # Alternate the build order per image: whichever build runs second on an
        # image reads it from a warm page cache, so a fixed order would bias wall time.
        for label, vol in (builds if index % 2 == 0 else builds[::-1]):
            if (label, item["stem"]) in seen:
                continue
            record = measure_one(label, vol, versions[label], item, args.work, args.timeout)
            append_record(jsonl, record)
            records.append(record)
            print(f"[{label}] {item['stem']}: {record['status']} rows={record['rows']} "
                  f"overlap={record['overlap_pct']}% wall={record['wall_s']}s", flush=True)  # fmt: skip
    refresh_la57_labels(records, all_items)
    return records


def refresh_la57_labels(records: List[Dict[str, Any]], items: List[Dict[str, Any]]) -> None:
    """Re-apply the current LA57 labels, so a resumed record never keeps a stale one."""
    by_stem = {item["stem"]: item for item in items}
    for record in records:
        item = by_stem.get(record["stem"])
        if item:
            record["la57_meta"], record["la57_ref"] = item["la57_meta"], item["la57_ref"]


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    records = run_all(args)
    if not records:
        return 0
    labels = [lb for lb, _ in parse_vol_args(args.vol)]
    if args.out_json:
        args.out_json.write_text(json.dumps({"records": records}, indent=2) + "\n")
    markdown = render_markdown(records, labels)
    if args.out_md:
        args.out_md.write_text(markdown)
    print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
