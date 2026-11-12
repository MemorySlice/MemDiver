#!/usr/bin/env python3
"""Build the public Zenodo DATA record of the x86 secrets captures (stdlib only).

For every published capture stem this writes, into ``--out``:

* ``<stem>.lime.xz``            the LiME image (xz, multi-threaded)
* ``<stem>.isf.json.xz``        the dwarf2json symbol table
* ``<stem>.containers.tar.xz``  the encrypted containers, when the capture has them (v2b)
* ``<stem>.meta.json``          acquisition metadata, sanitised (see below)
* ``<stem>.secrets.json``       the planted-secret ground truth (``memdiver-secrets-gt/1``)
* ``<stem>.secrets.tar.gz``     the guest-side artefacts the ground truth was taken from
* ``<stem>.ps_at_dump.txt`` / ``<stem>.vol3_pslist.txt``

plus ``SHA256SUMS`` (over every published file), ``SHA256SUMS.decompressed`` (the sha256 of
each file as ``scripts/fetch_contest_corpus.py`` lays it out), ``README.md`` and
``zenodo_record.json`` (record metadata for the Zenodo deposit form / API).

Sanitisation, applied to the published COPY only (the originals are never written):

* every published file is checked for the ``--redact`` words (case-insensitive, also UTF-16LE)
  and for host paths (``--host-path``, default: ``$HOME``); a hit in a file without a rewrite
  rule aborts the build;
* ``meta.json``: every ``*_path`` field becomes the bare published file name;
* images: each ``--redact`` word is overwritten in place by a SAME-LENGTH filler, so no offset
  moves; the offsets go into the published ``meta.json`` (``redactions``) together with the
  sha256 of the image as acquired, and ``dump_sha256`` becomes the published image's sha256.

Example (the contest submission folder lives outside the repository)::

    python tools/vol3_capture/package_zenodo.py \\
        --corpus "$MEMDIVER_SECRETS_CORPUS" --out ../vol3contest/zenodo --redact <word>
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

PUBLISHED_STEMS = (
    "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic",
    "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic",
    "ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic",
)
STEM_NOTES = {
    PUBLISHED_STEMS[0]: "capture v1, 4-level paging. Needed for the eCryptfs tag-3 claim (C-EC2): "
                        "the eCryptfs lower page 0 is resident only in v1.",
    PUBLISHED_STEMS[1]: "capture v1, 5-level paging (LA57) twin of the 4-level capture (C-LA57).",
    PUBLISHED_STEMS[2]: "capture v2b, 4-level paging: superset of v2 (LUKS2 volume key linked into the "
                        "keyring, fscrypt v1 logon key, libssh Tier A session, encrypted containers "
                        "for the mount proof) plus sibling process groups (dropbear, OpenSSH, gocryptfs) "
                        "and their physical frames.",
}
COMPRESSED = (".lime", ".isf.json", ".containers.tar")
OPTIONAL = (".containers.tar", ".vol3_pslist.txt")
VERBATIM = (".secrets.json", ".secrets.tar.gz", ".ps_at_dump.txt", ".vol3_pslist.txt")
REQUIRED = (".lime", ".isf.json", ".meta.json", ".secrets.json", ".secrets.tar.gz", ".ps_at_dump.txt")
FILLER = b"redacted"
CHUNK = 64 << 20
REPO_URL = "https://github.com/MemorySlice/MemDiver"
GT_SCHEMA_URL = REPO_URL + "/blob/main/tools/vol3_capture/README.md#sidecar-schema-memdiver-secrets-gt1"
DOI_TODO = "TODO: maintainer fills in the DOI after upload"


class LeakError(RuntimeError):
    """A published file would carry a withheld word or a host path."""


# --------------------------------------------------------------------------- sanitising


def variants(word: str) -> list:
    """The byte spellings of ``word`` that are redacted: lower/Title/UPPER, ASCII and UTF-16LE."""
    out = []
    for spelled in dict.fromkeys((word.lower(), word.title(), word.upper())):
        for enc in ("ascii", "utf-16-le"):
            out.append(spelled.encode(enc))
    return out


def filler_for(token: bytes) -> bytes:
    """A same-length replacement for ``token`` (UTF-16 tokens get a UTF-16 filler)."""
    if len(token) > 1 and token[1:2] == b"\x00":
        text = (FILLER.decode() * (len(token) // 2 // len(FILLER) + 1))[:len(token) // 2]
        return text.encode("utf-16-le")
    return (FILLER * (len(token) // len(FILLER) + 1))[:len(token)]


def leak_pattern(words, host_paths) -> re.Pattern:
    """Case-insensitive bytes regex for every withheld word (ASCII + UTF-16LE) and host path."""
    alts = []
    for word in words:
        alts.append(re.escape(word.encode()))
        alts.append(b"\\x00".join(re.escape(bytes([c])) for c in word.encode()))
    alts.extend(re.escape(p.encode()) for p in host_paths)
    return re.compile(b"(?i)(" + b"|".join(alts) + b")") if alts else re.compile(b"(?!)")


def check_clean(name: str, data: bytes, pattern: re.Pattern) -> None:
    hit = pattern.search(data)
    if hit:
        raise LeakError("%s: withheld word or host path at byte %d (%r)" % (name, hit.start(), hit.group(0)))


def sanitise_meta(meta: dict, stem: str) -> dict:
    """Published copy of ``meta.json``: every ``*_path`` is the bare file name a fetch lays out."""
    out = dict(meta)
    for key, value in meta.items():
        if key.endswith("_path") and isinstance(value, str) and value:
            out[key] = Path(value).name
    out["vm_name"] = stem
    return out


def redact_stream(src, sink, tokens, pattern: re.Pattern, chunk: int = CHUNK) -> dict:
    """Copy ``src`` to ``sink`` with every token overwritten in place; return offsets + sha256s.

    Matches across chunk boundaries are caught by carrying ``max_len - 1`` bytes. After the
    rewrite each emitted byte range is checked against ``pattern``; a residue raises LeakError.
    """
    keep = max((len(t) for t in tokens), default=1) - 1
    keep = max(keep, 64)
    before, after = hashlib.sha256(), hashlib.sha256()
    offsets, carry, base = [], b"", 0    # base = absolute offset of carry[0]
    while True:
        block = src.read(chunk)
        before.update(block)
        buf = bytearray(carry + block)
        for token in tokens:
            start = 0
            while True:
                at = buf.find(token, start)
                if at < 0:
                    break
                buf[at:at + len(token)] = filler_for(token)
                offsets.append({"offset": base + at, "length": len(token)})
                start = at + len(token)
        final = not block
        emit = len(buf) if final else max(0, len(buf) - keep)
        hit = pattern.search(bytes(buf))
        if hit and (final or hit.start() < emit):
            raise LeakError("image: residue after redaction at byte %d (%r)" % (base + hit.start(), hit.group(0)))
        out = bytes(buf[:emit])
        after.update(out)
        sink.write(out)
        carry, base = bytes(buf[emit:]), base + emit
        if final:
            break
    offsets.sort(key=lambda r: r["offset"])
    return {"redactions": offsets, "sha256_before": before.hexdigest(), "sha256_after": after.hexdigest(),
            "size": base}


# --------------------------------------------------------------------------- writing


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def xz_compress(src: Path, dst: Path, preset: str, tokens, pattern) -> dict:
    """``xz -T0 -<preset>`` of ``src`` (redacting tokens on the way) into ``dst`` atomically."""
    tmp = dst.with_name(dst.name + ".part")
    started = time.monotonic()
    with open(src, "rb") as fin, open(tmp, "wb") as fout:
        proc = subprocess.Popen(["xz", "-T0", "-" + preset, "-c"], stdin=subprocess.PIPE, stdout=fout)
        try:
            info = redact_stream(fin, proc.stdin, tokens, pattern)
        except BaseException:
            proc.kill()
            proc.wait()
            tmp.unlink(missing_ok=True)
            raise
        proc.stdin.close()
        if proc.wait() != 0:
            tmp.unlink(missing_ok=True)
            raise RuntimeError("xz failed on %s (rc %d)" % (src, proc.returncode))
    tmp.replace(dst)
    info["seconds"] = round(time.monotonic() - started, 1)
    return info


def plan(corpus: Path, stem: str) -> dict:
    """``{ext: source path}`` of one stem; raises if a required file is missing."""
    files = {ext: corpus / (stem + ext) for ext in REQUIRED + OPTIONAL}
    missing = [str(files[e]) for e in REQUIRED if not files[e].is_file()]
    if missing:
        raise FileNotFoundError("capture %s incomplete: %s" % (stem, ", ".join(missing)))
    return {ext: p for ext, p in files.items() if p.is_file()}


def package_stem(corpus: Path, out: Path, stem: str, preset: str, tokens, pattern, log) -> dict:
    """Publish one stem; returns ``{published name: decompressed name}`` and per-file stats."""
    files = plan(corpus, stem)
    small = {ext: files[ext].read_bytes() for ext in VERBATIM + (".meta.json",) if ext in files}
    for ext, data in small.items():
        if ext != ".meta.json":
            check_clean(stem + ext, data, pattern)
    published, stats, image = {}, {}, None
    for ext in COMPRESSED:
        if ext not in files:
            continue
        dst = out / (stem + ext + ".xz")
        log("compressing %s (xz -%s) ..." % (files[ext].name, preset))
        info = xz_compress(files[ext], dst, preset, tokens if ext == ".lime" else (), pattern)
        if ext != ".lime" and info["redactions"]:
            raise LeakError("%s%s holds a withheld word" % (stem, ext))
        stats[dst.name] = {"seconds": info["seconds"], "input_bytes": info["size"],
                           "sha256_decompressed": info["sha256_after"]}
        published[dst.name] = stem + ext
        if ext == ".lime":
            image = info
        log("  %s: %d -> %d bytes in %.1f s" % (dst.name, info["size"], dst.stat().st_size, info["seconds"]))
    for ext, data in small.items():
        if ext == ".meta.json":
            meta = sanitise_meta(json.loads(data), stem)
            if image is not None:
                meta["dump_sha256_as_acquired"] = image["sha256_before"]
                meta["dump_sha256"] = image["sha256_after"]
                meta["redactions"] = image["redactions"]
            data = (json.dumps(meta, indent=2) + "\n").encode()
            check_clean(stem + ext, data, pattern)
        (out / (stem + ext)).write_bytes(data)
        published[stem + ext] = stem + ext
    return {"published": published, "stats": stats, "redactions": image["redactions"] if image else []}


# --------------------------------------------------------------------------- record text


def citation_authors(cff: Path) -> list:
    """``[(family, given, orcid or None)]`` of the top-level ``authors:`` list of CITATION.cff."""
    authors, current, inside = [], None, False
    for line in cff.read_text().splitlines():
        if line.startswith("authors:"):
            inside = True
            continue
        if inside and line and not line.startswith(" "):
            break
        if not inside:
            continue
        m = re.match(r"\s*(-\s*)?(family-names|given-names|orcid):\s*\"?([^\"]+)\"?\s*$", line)
        if not m:
            continue
        if m.group(1) or current is None:
            current = {}
            authors.append(current)
        current[m.group(2)] = m.group(3).strip()
    return [(a.get("family-names", ""), a.get("given-names", ""), a.get("orcid")) for a in authors]


def record_metadata(authors: list, version: str) -> dict:
    creators = []
    for family, given, orcid in authors:
        entry = {"name": "%s, %s" % (family, given)}
        if orcid:
            entry["orcid"] = orcid.rsplit("/", 1)[-1]
        creators.append(entry)
    return {
        "upload_type": "dataset",
        "title": "MemDiver x86_64 Linux memory captures with planted-secret ground truth "
                 "(Volatility 3 plugin validation corpus)",
        "creators": creators,
        "description": (
            "<p>Three full-memory LiME captures of an Ubuntu 24.04 x86_64 guest (kernel 6.8.0-136-generic) "
            "in which known TEST secrets were planted before the dump: dm-crypt (LUKS1, LUKS2, VeraCrypt), "
            "fscrypt v1/v2, eCryptfs, gocryptfs, kernel WireGuard and SSH sessions. Each capture ships its "
            "Volatility 3 symbol table (ISF), a machine-readable ground-truth sidecar and the guest-side "
            "artefacts it was taken from. The corpus is the real-data gate (<code>make validate</code>) of the "
            "MemDiver Volatility 3 plugins.</p><p>All secrets are planted test values generated for this "
            "corpus; no production key or personal data is contained.</p>"),
        "access_right": "open",
        "license": "cc-by-4.0",
        "keywords": ["memory forensics", "Volatility 3", "Linux", "LiME", "ground truth", "dm-crypt",
                     "LUKS", "fscrypt", "eCryptfs", "gocryptfs", "WireGuard", "SSH", "key recovery",
                     "5-level paging"],
        "related_identifiers": [
            {"relation": "isSupplementTo", "identifier": REPO_URL, "resource_type": "software",
             "scheme": "url"},
        ],
        "version": version,
        "notes": "Software DOI: " + DOI_TODO + ".",
    }


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def readme(stems: list, sizes: dict, redactions: dict, authors: list) -> str:
    lines = [
        "# MemDiver x86_64 Linux memory captures with planted-secret ground truth",
        "",
        "Three full-memory captures (LiME) of an Ubuntu 24.04 x86_64 QEMU guest, kernel `6.8.0-136-generic`, "
        "made with the capture rig in [`tools/vol3_capture/`](%s/tree/main/tools/vol3_capture). "
        "Before each dump the rig planted known secrets and recorded them in a ground-truth sidecar." % REPO_URL,
        "",
        "**Every secret in this record is a planted test value generated for this corpus.** "
        "No production key, credential or personal data is contained.",
        "",
        "Authors: " + "; ".join("%s %s" % (g, f) for f, g, _o in authors) + ".",
        "",
        "## Captures",
        "",
    ]
    for stem in stems:
        lines += ["### `%s`" % stem, "", STEM_NOTES.get(stem, ""), ""]
        for name in sorted(n for n in sizes if n.startswith(stem + ".")):
            lines.append("- `%s` (%s)" % (name, human(sizes[name])))
        lines.append("")
    lines += [
        "## Files per capture",
        "",
        "| Suffix | Content |",
        "|---|---|",
        "| `.lime.xz` | full physical memory, LiME format (4 GiB guest) |",
        "| `.isf.json.xz` | Volatility 3 symbol table for the guest kernel (dwarf2json) |",
        "| `.secrets.json` | ground truth, schema `memdiver-secrets-gt/1` ([description](%s)) |" % GT_SCHEMA_URL,
        "| `.secrets.tar.gz` | guest-side artefacts the ground truth was taken from (`/proc/keys`, "
        "`dmsetup table --showkeys`, `wg show`, pahole layouts, ...) |",
        "| `.ps_at_dump.txt` | `ps` inside the guest right before the dump |",
        "| `.vol3_pslist.txt` | stock Volatility 3 `linux.pslist` on the image |",
        "| `.meta.json` | acquisition metadata (sizes, sha256, timestamps) |",
        "| `.containers.tar.xz` | v2b only: the encrypted containers (LUKS1/LUKS2/VeraCrypt/fscrypt images, "
        "eCryptfs lower dir, gocryptfs cipher dir) and the sha256 of every planted file, for the mount proof |",
        "",
        "`SHA256SUMS` covers every published file; `SHA256SUMS.decompressed` gives the sha256 of each "
        "file after decompression.",
        "",
        "## Use with MemDiver",
        "",
        "```sh",
        "git clone %s && cd MemDiver" % REPO_URL,
        "make validate CORPUS_FETCH=1 CORPUS_RECORD=<this record's id or URL> CORPUS_DIR=/path/to/corpus",
        "```",
        "",
        "`scripts/fetch_contest_corpus.py` downloads the record, verifies `SHA256SUMS`, decompresses the "
        "`.xz` files, lays the captures out as the gate expects and prints the "
        "`export MEMDIVER_SECRETS_CORPUS=...` line. A local copy works too: "
        "`make validate CORPUS_FETCH=1 CORPUS_MIRROR=/path/to/downloaded/record`.",
        "",
        "## Redaction",
        "",
        "One cloud-init SSH authorised-key COMMENT inside the guest carried the name of an unrelated "
        "internal project. In the published images that word was overwritten with a filler of the same "
        "length, so no offset moves; nothing a plugin or the gate reads is affected. Each capture's "
        "`.meta.json` lists the overwritten byte ranges (`redactions`), the sha256 of the image as "
        "acquired (`dump_sha256_as_acquired`) and of the published image (`dump_sha256`).",
        "",
    ]
    for stem in stems:
        lines.append("- `%s`: %d range(s)" % (stem, len(redactions.get(stem, []))))
    lines += [
        "",
        "## Licence",
        "",
        "Data: [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). "
        "The MemDiver software is Apache-2.0 (%s)." % REPO_URL,
        "",
        "Software DOI: " + DOI_TODO + ".",
        "",
    ]
    return "\n".join(lines)


def write_sums(out: Path, names, path_name: str, digests: dict = None) -> dict:
    digests = digests if digests is not None else {n: sha256_file(out / n) for n in sorted(names)}
    (out / path_name).write_text("".join("%s  %s\n" % (digests[n], n) for n in sorted(digests)))
    return digests


def build(corpus: Path, out: Path, stems, preset: str, words, host_paths, version: str, cff: Path,
          log=print) -> dict:
    pattern = leak_pattern(words, host_paths)
    tokens = [t for w in words for t in variants(w)]
    out.mkdir(parents=True, exist_ok=True)
    published, stats, redactions = {}, {}, {}
    for stem in stems:
        res = package_stem(corpus, out, stem, preset, tokens, pattern, log)
        published.update(res["published"])
        stats.update(res["stats"])
        redactions[stem] = res["redactions"]
    sizes = {n: (out / n).stat().st_size for n in published}
    authors = citation_authors(cff)
    text = readme(list(stems), sizes, redactions, authors)
    meta = json.dumps(record_metadata(authors, version), indent=2) + "\n"
    for name, data in (("README.md", text.encode()), ("zenodo_record.json", meta.encode())):
        check_clean(name, data, pattern)
        (out / name).write_bytes(data)
    digests = write_sums(out, list(published) + ["README.md", "zenodo_record.json"], "SHA256SUMS")
    decompressed = {laid_out: (stats[name]["sha256_decompressed"] if name.endswith(".xz") else digests[name])
                    for name, laid_out in published.items()}
    write_sums(out, decompressed, "SHA256SUMS.decompressed", decompressed)
    return {"stats": stats, "redactions": redactions, "digests": digests, "sizes": sizes}


def main(argv=None) -> int:
    repo = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.environ.get("MEMDIVER_SECRETS_CORPUS", ""),
                    help="directory with the captures (default: $MEMDIVER_SECRETS_CORPUS)")
    ap.add_argument("--out", required=True, help="output directory, e.g. ../vol3contest/zenodo")
    ap.add_argument("--stem", action="append", dest="stems", help="capture stem (repeatable; default: the 3 published)")
    ap.add_argument("--xz-preset", default="6", help="xz preset (default 6; 1 is ~6x faster, ~8%% larger)")
    ap.add_argument("--redact", action="append", default=[], metavar="WORD",
                    help="withheld word: same-length overwrite in images, abort elsewhere (repeatable)")
    ap.add_argument("--host-path", action="append", default=None, metavar="PATH",
                    help="host path that must not appear in any published file (default: $HOME)")
    ap.add_argument("--version", default="1.0", help="record version (default 1.0)")
    args = ap.parse_args(argv)
    if not args.corpus or not Path(args.corpus).is_dir():
        ap.error("--corpus (or MEMDIVER_SECRETS_CORPUS) must be a directory")
    if shutil.which("xz") is None:
        ap.error("xz not found on PATH")
    host_paths = args.host_path if args.host_path is not None else [str(Path.home())]
    try:
        res = build(Path(args.corpus), Path(args.out), args.stems or PUBLISHED_STEMS, args.xz_preset,
                    args.redact, host_paths, args.version, repo / "CITATION.cff")
    except (LeakError, FileNotFoundError) as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2
    for name in sorted(res["digests"]):
        print("%-72s %12d  %s" % (name, (Path(args.out) / name).stat().st_size, res["digests"][name][:16]))
    for name, s in sorted(res["stats"].items()):
        print("timing %s: %.1f s for %d input bytes" % (name, s["seconds"], s["input_bytes"]))
    for stem, ranges in res["redactions"].items():
        print("redactions %s: %s" % (stem, [r["offset"] for r in ranges]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
