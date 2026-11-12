"""Rebuild the in-repo Volatility 3 samples from the gocryptfs ``.msl`` corpus.

This script documents how every file in ``samples/`` was made; judges never need to run it
(the outputs are committed, see ``SHA256SUMS``). It needs MemDiver and the private gocryptfs
corpus (``MEMDIVER_GOCRYPTFS_CORPUS`` = the ``dataset_gocryptfs`` directory holding
``run_NNNN/{memslicer.msl,meta.json,cipher/}``)::

    MEMDIVER_GOCRYPTFS_CORPUS=/abs/dataset_gocryptfs python samples/build_samples.py

Outputs (written next to this script):

* ``gocryptfs_aes.msl.gz`` / ``gocryptfs_xchacha.msl.gz`` -- ``run_0001`` (aes-gcm) and
  ``run_0002`` (xchacha20-poly1305) region-filtered with ``msl.importer.import_msl_passthrough``
  (``materialize=True``): only the Go heap arena that holds the master key is kept. gzip only
  wraps the file for the repository; ``gunzip -k`` gives the ``.msl`` byte for byte.
* ``gocryptfs_<cipher>.oracle`` -- the vault oracle sample (``gocryptfs_gcm.sample_from_vault``):
  the FeatureFlags of ``gocryptfs.conf`` plus the first block of one content file. It holds no
  ``EncryptedKey``/scrypt parameters, so it is no password-cracking target.
* ``gocryptfs_aes_tampered.msl.gz`` -- the aes slice with ONE byte flipped: the first byte of the
  first in-memory copy of the master key.
* ``gocryptfs_aes_encrypted.msl`` + ``.key`` -- the aes slice re-written with zstd-compressed
  regions and AES-256-GCM container encryption under a public 32-byte demo key.
* ``plugins/memdiver_gocryptfs.py`` (+ ``.recipe.json``) -- the plugin MemDiver synthesizes from
  the two slices (``synthesize_vol3_plugin``); it runs under stock vol without MemDiver.
* ``samples.json`` -- provenance and ground truth of every sample.

``SHA256SUMS`` is rewritten last.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from memdiver.msl.enums import CompAlgo
from memdiver.msl.importer import import_msl_passthrough
from memdiver.msl.materialize import RegionByteSource, RegionMaterializer
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import ALL_CATEGORIES, RegionSelection
from memdiver.msl.writer import MslEncryptionConfig
from memdiver.oracles.formats import gocryptfs_gcm

HERE = Path(__file__).resolve().parent
RUNS = {"aes": "run_0001", "xchacha": "run_0002"}
ORACLE_KIND = "gocryptfs-gcm"
PLUGIN_NAME = "memdiver_gocryptfs"
#: Public demo key of the encrypted sample. Deterministic so a rebuild uses the same key file.
DEMO_KEY = hashlib.sha256(b"memdiver vol3 contest 2026: public demo key for the encrypted sample").digest()
GZIP_MTIME = 0  # reproducible gzip headers


@dataclasses.dataclass(frozen=True)
class KeyRegionSelection(RegionSelection):
    """Keep exactly the regions that contain one of ``vas`` (the in-memory key copies)."""

    vas: tuple = ()

    @property
    def is_all(self) -> bool:
        return False

    def includes(self, info) -> bool:
        return any(info.base_addr <= va < info.base_addr + info.size for va in self.vas)

    def to_note(self) -> str:
        return "regions=key-holding(" + ",".join("%#x" % va for va in self.vas) + ")"


class _CompressingMaterializer(RegionMaterializer):
    """``RegionMaterializer`` that writes every kept region zstd-compressed (in memory)."""

    def _add_region(self, stored) -> None:
        region = stored.region
        source = RegionByteSource(self._reader, stored)
        self._writer.add_memory_region(
            region.base_addr, bytes(source(0, source.data_len)), protection=region.protection,
            region_type=region.region_type, page_size_log2=region.page_size_log2,
            timestamp_ns=region.timestamp_ns, page_states=[int(s) for s in region.page_states],
            compression=CompAlgo.ZSTD)
        self.stats.regions_written += 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def key_vas(msl: Path, key: bytes) -> list:
    """Every VA of ``key`` in the slice (MemDiver's reader, captured runs only)."""
    from memdiver.core.dump_source import MslDumpSource

    found = []
    with MslDumpSource(msl) as source:
        for va, length, vas_offset in source.captured_runs():
            data = source.read_range(vas_offset, length, view="vas")
            at = data.find(key)
            while at >= 0:
                found.append(va + at)
                at = data.find(key, at + 1)
    return found


def region_summary(msl: Path) -> list:
    from memdiver.msl.import_preview import msl_source_format
    from memdiver.msl.materialize import stored_regions

    with MslReader(msl) as reader:
        return [{"base": "%#x" % s.info.base_addr, "size": s.info.size, "category": s.info.category.value}
                for s in stored_regions(reader, msl_source_format(reader))]


def gzip_to(src: Path, dst: Path) -> None:
    with open(src, "rb") as raw, open(dst, "wb") as out:
        with gzip.GzipFile(filename=src.name, mode="wb", compresslevel=9, fileobj=out,
                           mtime=GZIP_MTIME) as packed:
            shutil.copyfileobj(raw, packed, 1 << 20)


def build_slice(run: Path, cipher: str, work: Path) -> dict:
    meta = json.loads((run / "meta.json").read_text())
    key = bytes.fromhex(meta["master_key_hex"])
    source = run / "memslicer.msl"
    vas = tuple(key_vas(source, key))
    out = work / ("gocryptfs_%s.msl" % cipher)
    selection = KeyRegionSelection(ALL_CATEGORIES, vas=vas)
    result = import_msl_passthrough(source, out, selection=selection, materialize=True)
    assert result.materialized and key_vas(out, key) == list(vas), (run, vas)
    gzip_to(out, HERE / (out.name + ".gz"))
    oracle = HERE / ("gocryptfs_%s.oracle" % cipher)
    oracle.write_bytes(gocryptfs_gcm.sample_from_vault(str(run / "cipher")))
    return {
        "file": out.name + ".gz", "msl": out.name, "msl_sha256": sha256_file(out),
        "oracle_sample": oracle.name, "cipher": meta["cipher"], "pid": meta["pid"],
        "master_key_hex": meta["master_key_hex"], "key_vas": ["%#x" % va for va in vas],
        "source": {"corpus_run": run.name, "file": "memslicer.msl", "bytes": source.stat().st_size,
                   "sha256": sha256_file(source), "capture_tool": "memslicer",
                   "program": "gocryptfs (Go, /usr/bin/gocryptfs) on Linux x86_64"},
        "kept_regions": region_summary(out), "selection": selection.to_note(),
    }


def build_tampered(work: Path, aes: dict) -> dict:
    src, out = work / aes["msl"], work / "gocryptfs_aes_tampered.msl"
    data = bytearray(src.read_bytes())
    key = bytes.fromhex(aes["master_key_hex"])
    offset = data.find(key)
    assert offset >= 0 and data.find(key, offset + 1) > offset  # two copies; the second stays intact
    data[offset] ^= 0x01
    out.write_bytes(bytes(data))
    gzip_to(out, HERE / (out.name + ".gz"))
    return {"file": out.name + ".gz", "msl": out.name, "msl_sha256": sha256_file(out),
            "derived_from": aes["msl"], "flipped_file_offset": offset, "xor": "0x01",
            "flipped_va": aes["key_vas"][0], "intact_key_va": aes["key_vas"][1]}


def build_encrypted(work: Path, aes: dict) -> dict:
    src, out = work / aes["msl"], HERE / "gocryptfs_aes_encrypted.msl"
    key_file = HERE / "gocryptfs_aes_encrypted.msl.key"
    key_file.write_bytes(DEMO_KEY)
    from memdiver.msl.import_preview import msl_source_format
    from memdiver.msl.materialize import stored_regions

    with MslReader(src) as reader:
        regions = stored_regions(reader, msl_source_format(reader))
        config = MslEncryptionConfig(raw_key=DEMO_KEY)
        _CompressingMaterializer(reader, src, out, regions, [True] * len(regions),
                                 "regions=all;zstd=1;encrypted=aes-256-gcm", config).run()
    assert key_vas(src, bytes.fromhex(aes["master_key_hex"])) == [int(v, 16) for v in aes["key_vas"]]
    return {"file": out.name, "key_file": key_file.name, "derived_from": aes["msl"],
            "encryption": "AES-256-GCM, raw 32-byte key (public demo key)", "compression": "zstd"}


def build_plugin(work: Path, slices: dict) -> dict:
    from memdiver.services import synthesize_vol3_plugin

    case = work / "case"
    case.mkdir()
    order = [slices["aes"], slices["xchacha"]]
    result = synthesize_vol3_plugin(
        dump_paths=[str(work / s["msl"]) for s in order], name=PLUGIN_NAME,
        key_hex=[s["master_key_hex"] for s in order], oracle_kind=ORACLE_KIND,
        oracle_sample_path=[str(HERE / s["oracle_sample"]) for s in order],
        case_dir=str(case))
    assert result["proven"], result["verdicts"]
    plugins = HERE / "plugins"
    plugins.mkdir(exist_ok=True)
    shutil.copyfile(result["stored"]["path"], plugins / (PLUGIN_NAME + ".py"))
    shutil.copyfile(result["stored"]["recipe_path"], plugins / (PLUGIN_NAME + ".recipe.json"))
    return {"file": "plugins/%s.py" % PLUGIN_NAME, "recipe": "plugins/%s.recipe.json" % PLUGIN_NAME,
            "vol_plugin": result["vol_command"].split()[-1] if result.get("vol_command") else None,
            "trained_on": [s["msl"] for s in order], "oracle_kind": ORACLE_KIND}


#: Not sample data: the docs and this script change without changing any sample.
NOT_SUMMED = {"SHA256SUMS", "README.md", Path(__file__).name, "build_wireguard_go_sample.py"}


def write_sums() -> None:
    names = sorted(p.relative_to(HERE).as_posix() for p in HERE.rglob("*")
                   if p.is_file() and p.name not in NOT_SUMMED and "__pycache__" not in p.parts)
    lines = ["%s  %s\n" % (sha256_file(HERE / n), n) for n in names]
    (HERE / "SHA256SUMS").write_text("".join(lines))


def main() -> int:
    corpus = Path(os.environ.get("MEMDIVER_GOCRYPTFS_CORPUS", ""))
    if not (corpus / RUNS["aes"] / "memslicer.msl").is_file():
        print("set MEMDIVER_GOCRYPTFS_CORPUS to the dataset_gocryptfs directory", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="memdiver-samples-") as tmp:
        work = Path(tmp)
        slices = {c: build_slice(corpus / run, c, work) for c, run in RUNS.items()}
        manifest = {"schema": "memdiver-samples/1", "slices": slices,
                    "tampered": build_tampered(work, slices["aes"]),
                    "encrypted": build_encrypted(work, slices["aes"]),
                    "plugin": build_plugin(work, slices)}
    (HERE / "samples.json").write_text(json.dumps(manifest, indent=2) + "\n")
    write_sums()
    return 0


if __name__ == "__main__":
    sys.exit(main())
