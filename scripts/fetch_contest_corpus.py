#!/usr/bin/env python3
"""Fetch the public x86 secrets-capture corpus and lay it out for ``make validate`` (stdlib only).

Sources (exactly one):

* ``--record <id | https://zenodo.org/records/<id> | DOI URL>``: downloads every file of the
  Zenodo record (``https://zenodo.org/api/records/<id>``) into ``<target>/_download/``;
* ``--mirror <dir>``: a local copy of the record (read in place, nothing is copied twice).

Then: every file listed in ``SHA256SUMS`` must be present and match, otherwise NOTHING is laid
out (exit 2). ``.xz`` files are decompressed (``lzma``) and every other data file is copied
into ``<target>/``, under exactly the names the gate expects
(``<stem>.{lime,isf.json,secrets.json,secrets.tar.gz,meta.json,ps_at_dump.txt,...}``); each
laid-out file is checked against ``SHA256SUMS.decompressed`` when the record has one. Files
already laid out with the right sha256 are kept (a re-run is cheap). The last line printed is
``export MEMDIVER_SECRETS_CORPUS=<target>``.
"""

import argparse
import hashlib
import json
import lzma
import re
import shlex
import shutil
import sys
import urllib.request
from pathlib import Path

SUMS = "SHA256SUMS"
SUMS_DECOMPRESSED = "SHA256SUMS.decompressed"
RECORD_ONLY = {SUMS, SUMS_DECOMPRESSED, "README.md", "zenodo_record.json"}
GATE_REQUIRED = (".lime", ".isf.json", ".secrets.json")
ZENODO_API = "https://zenodo.org/api/records/"
CHUNK = 16 << 20
USER_AGENT = "memdiver-fetch-contest-corpus"


class FetchError(RuntimeError):
    """The corpus could not be fetched or failed verification."""


# --------------------------------------------------------------------------- checksums


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def parse_sums(text: str) -> dict:
    """``{name: sha256}`` of a ``sha256sum`` file; rejects path separators and malformed lines."""
    sums = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
        if not m or "/" in m.group(2) or "\\" in m.group(2) or m.group(2) in (".", ".."):
            raise FetchError("%s line %d is malformed or names a path: %r" % (SUMS, number, line))
        sums[m.group(2)] = m.group(1).lower()
    if not sums:
        raise FetchError("%s is empty" % SUMS)
    return sums


def verify(source: Path, sums: dict) -> None:
    """Every listed file exists in ``source`` with the listed sha256; else FetchError (all reported)."""
    bad = []
    for name, digest in sorted(sums.items()):
        path = source / name
        if not path.is_file():
            bad.append("%s: missing" % name)
        elif sha256_file(path) != digest:
            bad.append("%s: sha256 mismatch" % name)
    if bad:
        raise FetchError("checksum verification failed, nothing laid out:\n  " + "\n  ".join(bad))


# --------------------------------------------------------------------------- download


def record_id(record: str) -> str:
    """The numeric Zenodo record id of an id, a record URL or a ``10.5281/zenodo.<id>`` DOI."""
    if not record.strip():
        raise FetchError("no Zenodo record given: pass --record (CORPUS_RECORD=) or --mirror (CORPUS_MIRROR=)")
    m = re.search(r"(?:zenodo\.|records?/)(\d+)", record) or re.fullmatch(r"\s*(\d+)\s*", record)
    if not m:
        raise FetchError("cannot read a Zenodo record id from %r" % record)
    return m.group(1)


def _open(url: str):
    if not url.startswith("https://"):
        raise FetchError("refusing a non-https URL: %r" % url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    # https only (checked above)
    return urllib.request.urlopen(request, timeout=120)  # nosec B310


def record_files(record: str, opener=_open) -> dict:
    """``{file name: download URL}`` from the Zenodo records API."""
    with opener(ZENODO_API + record_id(record)) as resp:
        meta = json.load(resp)
    files = {}
    for entry in meta.get("files", []):
        name = entry.get("key") or entry.get("filename")
        link = (entry.get("links") or {}).get("self") or (entry.get("links") or {}).get("download")
        if name and link:
            files[name] = link
    if SUMS not in files:
        raise FetchError("record %s has no %s" % (record, SUMS))
    return files


def download(files: dict, dest: Path, opener=_open, log=print) -> None:
    """Download each file into ``dest`` (atomic rename; files already present are re-verified later)."""
    dest.mkdir(parents=True, exist_ok=True)
    for name, url in sorted(files.items()):
        if "/" in name or name in (".", ".."):
            raise FetchError("record file name %r is not a plain name" % name)
        target = dest / name
        if target.is_file():
            continue
        log("downloading %s ..." % name)
        part = target.with_name(name + ".part")
        with opener(url) as resp, open(part, "wb") as out:
            shutil.copyfileobj(resp, out, CHUNK)
        part.replace(target)


# --------------------------------------------------------------------------- layout


def laid_out_name(name: str) -> str:
    return name[:-3] if name.endswith(".xz") else name


def _write_atomic(target: Path, reader) -> str:
    part = target.with_name(target.name + ".part")
    h = hashlib.sha256()
    try:
        with open(part, "wb") as out:
            for block in iter(lambda: reader.read(CHUNK), b""):
                h.update(block)
                out.write(block)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    part.replace(target)
    return h.hexdigest()


def lay_out(source: Path, target: Path, sums: dict, expected: dict, log=print) -> list:
    """Decompress / copy every data file of ``sums`` into ``target``; returns the laid-out names."""
    target.mkdir(parents=True, exist_ok=True)
    done = []
    for name in sorted(n for n in sums if n not in RECORD_ONLY):
        out_name = laid_out_name(name)
        dst = target / out_name
        want = expected.get(out_name) or (None if name.endswith(".xz") else sums[name])
        if dst.is_file() and want and sha256_file(dst) == want:
            log("kept      %s (sha256 ok)" % out_name)
            done.append(out_name)
            continue
        log(("decompress" if name.endswith(".xz") else "copy      ") + " %s" % out_name)
        opener = lzma.open if name.endswith(".xz") else open
        with opener(source / name, "rb") as reader:
            got = _write_atomic(dst, reader)
        if want and got != want:
            dst.unlink()
            raise FetchError("%s: sha256 after layout %s != expected %s" % (out_name, got, want))
        done.append(out_name)
    return done


def stems_ready(target: Path, names) -> list:
    """Capture stems that have every file the gate needs."""
    stems = {n[:-len(".lime")] for n in names if n.endswith(".lime")}
    return sorted(s for s in stems if all((target / (s + ext)).is_file() for ext in GATE_REQUIRED))


def fetch(target: Path, record: str = None, mirror: Path = None, opener=_open, log=print) -> list:
    if (record is None) == (mirror is None):
        raise FetchError("give exactly one of --record or --mirror")
    if mirror is not None:
        source = Path(mirror)
        if not (source / SUMS).is_file():
            raise FetchError("mirror %s has no %s" % (source, SUMS))
    else:
        source = target / "_download"
        download(record_files(record, opener), source, opener, log)
    sums = parse_sums((source / SUMS).read_text())
    verify(source, sums)
    log("%s: %d files verified" % (SUMS, len(sums)))
    expected = parse_sums((source / SUMS_DECOMPRESSED).read_text()) \
        if (source / SUMS_DECOMPRESSED).is_file() else {}
    names = lay_out(source, target, sums, expected, log)
    stems = stems_ready(target, names)
    if not stems:
        raise FetchError("no complete capture (%s) after layout" % ", ".join(GATE_REQUIRED))
    return stems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--record", help="Zenodo record id, record URL or DOI")
    src.add_argument("--mirror", help="local directory holding the record's files")
    ap.add_argument("--target", required=True, help="directory to lay the corpus out in")
    ap.add_argument("--keep-downloads", action="store_true", help="keep <target>/_download after --record")
    args = ap.parse_args(argv)
    target = Path(args.target).expanduser().resolve()
    try:
        stems = fetch(target, record=args.record, mirror=Path(args.mirror) if args.mirror else None)
    except (FetchError, OSError, lzma.LZMAError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    if args.record and not args.keep_downloads:
        shutil.rmtree(target / "_download", ignore_errors=True)
    for stem in stems:
        print("capture ready: %s" % stem)
    print("export MEMDIVER_SECRETS_CORPUS=%s" % shlex.quote(str(target)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
