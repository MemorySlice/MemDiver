"""scripts/fetch_contest_corpus.py + tools/vol3_capture/package_zenodo.py on synthetic captures.

No test touches the network: ``urllib.request.urlopen`` is replaced by a guard that fails, and the
``--record`` path is driven through a fake opener that serves files from a local directory.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import sys
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fetch = _load("_fetch_contest_corpus", REPO / "scripts" / "fetch_contest_corpus.py")
pkg = _load("_package_zenodo", REPO / "tools" / "vol3_capture" / "package_zenodo.py")

WORD = "hushproj"          # synthetic withheld word
STEM = "synthetic-x86-4level_1.0-generic"
needs_xz = pytest.mark.skipif(shutil.which("xz") is None, reason="xz not on PATH")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network access in a unit test")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _capture(root: Path, stem: str = STEM, image: bytes = None, containers: bool = True) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    image = image if image is not None else (b"\x00" * 5000 + b"key " + WORD.encode() + b"@local" + bytes(range(256)) * 40)
    files = {
        ".lime": image,
        ".isf.json": b'{"symbols": {}}',
        ".meta.json": json.dumps({"dump_path": "experiments/x/%s.lime" % stem, "isf_path": "e/%s.isf.json" % stem,
                                  "dump_sha256": _sha(image), "notes": "n"}).encode(),
        ".secrets.json": b'{"schema": "memdiver-secrets-gt/1"}',
        ".secrets.tar.gz": b"\x1f\x8bfake",
        ".ps_at_dump.txt": b"PID CMD\n1 init\n",
        ".vol3_pslist.txt": b"PID\n1\n",
    }
    if containers:
        files[".containers.tar"] = b"tar" * 1000
    for ext, data in files.items():
        (root / (stem + ext)).write_bytes(data)
    return files


def _package(corpus: Path, out: Path, words=(WORD,), host_paths=("/Users/someone",)) -> dict:
    return pkg.build(corpus, out, [STEM], "0", list(words), list(host_paths), "1.0", REPO / "CITATION.cff",
                     log=lambda *_a: None)


# --------------------------------------------------------------------------- fetch: checksums


def test_parse_sums_reads_sha256sum_format_and_rejects_paths():
    digest = "a" * 64
    assert fetch.parse_sums("%s  x.lime.xz\n%s *y.json\n" % (digest, digest)) == {"x.lime.xz": digest,
                                                                                 "y.json": digest}
    for bad in ("%s  ../x" % digest, "%s  sub/x" % digest, "nothex  x", ""):
        with pytest.raises(fetch.FetchError):
            fetch.parse_sums(bad)


def test_verify_reports_missing_and_mismatched_files(tmp_path):
    (tmp_path / "a").write_bytes(b"one")
    (tmp_path / "b").write_bytes(b"two")
    with pytest.raises(fetch.FetchError) as err:
        fetch.verify(tmp_path, {"a": _sha(b"one"), "b": _sha(b"TWO"), "c": _sha(b"")})
    assert "b: sha256 mismatch" in str(err.value) and "c: missing" in str(err.value)
    fetch.verify(tmp_path, {"a": _sha(b"one"), "b": _sha(b"two")})


def test_record_id_accepts_id_url_and_doi():
    assert fetch.record_id("1234567") == "1234567"
    assert fetch.record_id("https://zenodo.org/records/1234567") == "1234567"
    assert fetch.record_id("https://doi.org/10.5281/zenodo.1234567") == "1234567"
    for bad in ("", "not-a-record"):
        with pytest.raises(fetch.FetchError):
            fetch.record_id(bad)


def test_laid_out_name_strips_xz_only():
    assert fetch.laid_out_name("s.lime.xz") == "s.lime"
    assert fetch.laid_out_name("s.secrets.tar.gz") == "s.secrets.tar.gz"


# --------------------------------------------------------------------------- packager units


def test_redaction_variants_and_fillers_keep_length():
    tokens = pkg.variants(WORD)
    assert WORD.encode() in tokens and WORD.upper().encode("utf-16-le") in tokens
    for token in tokens:
        assert len(pkg.filler_for(token)) == len(token) and pkg.filler_for(token) != token


def test_redact_stream_catches_a_token_across_a_chunk_boundary():
    data = bytearray(b"A" * 300)
    data[60:68] = WORD.encode()                   # straddles the 64-byte chunk boundary
    data[200:216] = WORD.title().encode("utf-16-le")
    sink = io.BytesIO()
    pattern = pkg.leak_pattern([WORD], [])
    info = pkg.redact_stream(io.BytesIO(bytes(data)), sink, pkg.variants(WORD), pattern, chunk=64)
    out = sink.getvalue()
    assert len(out) == len(data) == info["size"]
    assert [r["offset"] for r in info["redactions"]] == [60, 200]
    assert not pattern.search(out)
    assert info["sha256_before"] == _sha(bytes(data)) and info["sha256_after"] == _sha(out)
    diff = [i for i in range(len(out)) if out[i] != data[i]]
    assert diff and all(60 <= i < 68 or 200 <= i < 216 for i in diff)


def test_sanitise_meta_reduces_paths_to_published_names():
    meta = pkg.sanitise_meta({"dump_path": "/Users/x/a/s.lime", "isf_path": "e/s.isf.json", "n": 1}, "s")
    assert (meta["dump_path"], meta["isf_path"], meta["n"], meta["vm_name"]) == ("s.lime", "s.isf.json", 1, "s")


def test_citation_authors_reads_the_repo_citation_file():
    authors = pkg.citation_authors(REPO / "CITATION.cff")
    assert authors and authors[0][:2] == ("Baier", "Daniel")
    meta = pkg.record_metadata(authors, "1.0")
    assert meta["license"] == "cc-by-4.0" and meta["creators"][0]["name"] == "Baier, Daniel"
    assert meta["related_identifiers"][0]["identifier"] == pkg.REPO_URL


@needs_xz
def test_packager_refuses_a_withheld_word_in_a_verbatim_file(tmp_path):
    _capture(tmp_path / "c")
    (tmp_path / "c" / (STEM + ".ps_at_dump.txt")).write_bytes(b"1 /opt/" + WORD.upper().encode() + b"/run\n")
    with pytest.raises(pkg.LeakError):
        _package(tmp_path / "c", tmp_path / "out")
    assert not list((tmp_path / "out").glob("*.xz"))       # refused before any compression


@needs_xz
def test_packager_refuses_a_host_path(tmp_path):
    _capture(tmp_path / "c")
    (tmp_path / "c" / (STEM + ".secrets.json")).write_bytes(b'{"p": "/Users/someone/x"}')
    with pytest.raises(pkg.LeakError):
        _package(tmp_path / "c", tmp_path / "out")


# --------------------------------------------------------------------------- round trip


@needs_xz
def test_package_then_fetch_round_trip(tmp_path, capsys):
    originals = _capture(tmp_path / "c")
    res = _package(tmp_path / "c", tmp_path / "rec")
    rec = tmp_path / "rec"
    assert {STEM + ".lime.xz", STEM + ".isf.json.xz", STEM + ".containers.tar.xz", "SHA256SUMS",
            "SHA256SUMS.decompressed", "README.md", "zenodo_record.json"} <= {p.name for p in rec.iterdir()}
    for path in rec.iterdir():
        assert WORD.encode() not in path.read_bytes().lower()
    assert len(res["redactions"][STEM]) == 1

    target = tmp_path / "corpus with space"
    assert fetch.main(["--mirror", str(rec), "--target", str(target)]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out[-1] == "export MEMDIVER_SECRETS_CORPUS='%s'" % target
    assert "capture ready: %s" % STEM in out

    for ext, data in originals.items():
        got = (target / (STEM + ext)).read_bytes()
        if ext == ".lime":
            [r] = res["redactions"][STEM]
            assert len(got) == len(data) and got[:r["offset"]] == data[:r["offset"]]
            assert got[r["offset"] + r["length"]:] == data[r["offset"] + r["length"]:]
        elif ext == ".meta.json":
            meta = json.loads(got)
            assert meta["dump_sha256"] == _sha((target / (STEM + ".lime")).read_bytes())
            assert meta["dump_sha256_as_acquired"] == _sha(originals[".lime"])
            assert meta["dump_path"] == STEM + ".lime"
        else:
            assert got == data, ext
    assert not (target / "README.md").exists() and not list(target.glob("*.xz"))

    # a re-run keeps the laid-out files (sha256 ok) instead of decompressing again
    logs = []
    fetch.fetch(target, mirror=rec, log=logs.append)
    assert all(line.startswith(("kept", "SHA256SUMS")) for line in logs), logs


@needs_xz
def test_checksum_mismatch_is_refused_and_nothing_is_laid_out(tmp_path, capsys):
    _capture(tmp_path / "c")
    _package(tmp_path / "c", tmp_path / "rec")
    victim = tmp_path / "rec" / (STEM + ".secrets.json")
    victim.write_bytes(victim.read_bytes() + b" ")
    target = tmp_path / "t"
    assert fetch.main(["--mirror", str(tmp_path / "rec"), "--target", str(target)]) == 2
    assert "sha256 mismatch" in capsys.readouterr().err
    assert not target.exists() or not any(target.iterdir())


@needs_xz
def test_decompressed_content_mismatch_is_refused(tmp_path):
    _capture(tmp_path / "c")
    _package(tmp_path / "c", tmp_path / "rec")
    sums = tmp_path / "rec" / "SHA256SUMS.decompressed"
    sums.write_text(sums.read_text().replace(_sha(b'{"symbols": {}}'), "0" * 64))
    with pytest.raises(fetch.FetchError, match="after layout"):
        fetch.fetch(tmp_path / "t", mirror=tmp_path / "rec", log=lambda *_a: None)
    assert not (tmp_path / "t" / (STEM + ".isf.json")).exists()


def test_mirror_without_sums_and_incomplete_capture_are_refused(tmp_path):
    with pytest.raises(fetch.FetchError, match="SHA256SUMS"):
        fetch.fetch(tmp_path / "t", mirror=tmp_path)
    (tmp_path / "x.secrets.json").write_bytes(b"{}")
    (tmp_path / "SHA256SUMS").write_text("%s  x.secrets.json\n" % _sha(b"{}"))
    with pytest.raises(fetch.FetchError, match="no complete capture"):
        fetch.fetch(tmp_path / "t", mirror=tmp_path, log=lambda *_a: None)


def test_exactly_one_source_is_required(tmp_path):
    with pytest.raises(fetch.FetchError):
        fetch.fetch(tmp_path, record=None, mirror=None)
    with pytest.raises(fetch.FetchError):
        fetch.fetch(tmp_path, record="1", mirror=tmp_path)


@needs_xz
def test_record_download_through_a_fake_zenodo(tmp_path, capsys):
    _capture(tmp_path / "c")
    _package(tmp_path / "c", tmp_path / "rec")
    served = {p.name: p for p in (tmp_path / "rec").iterdir()}
    api = {"files": [{"key": n, "links": {"self": "https://zenodo.invalid/f/" + n}} for n in served]}
    asked = []

    def opener(url):
        asked.append(url)
        if url == fetch.ZENODO_API + "4242":
            return io.BytesIO(json.dumps(api).encode())
        return io.BytesIO(served[url.rsplit("/", 1)[-1]].read_bytes())

    stems = fetch.fetch(tmp_path / "t", record="https://zenodo.org/records/4242", opener=opener,
                        log=lambda *_a: None)
    assert stems == [STEM] and asked[0] == fetch.ZENODO_API + "4242"
    assert (tmp_path / "t" / (STEM + ".lime")).is_file()


def test_record_download_rejects_a_path_like_file_name(tmp_path):
    with pytest.raises(fetch.FetchError):
        fetch.download({"../evil": "https://zenodo.invalid/x"}, tmp_path, opener=lambda u: io.BytesIO(b""))


def test_default_opener_refuses_non_https_urls():
    for url in ("file:///etc/passwd", "http://zenodo.org/api/records/1", "ftp://x/y"):
        with pytest.raises(fetch.FetchError, match="non-https"):
            fetch._open(url)
