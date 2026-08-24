#!/usr/bin/env python3
"""Generate the committed pcap-oracle e2e fixture: a matched (pcap, .msl) pair.

The goal is a *committed, self-verifying* fixture that proves — through the exact
same ``search-reduce -> brute-force`` path the web pipeline runs — that a TLS key
recovered from a synthetic memory dump decrypts a REAL captured TLS 1.3 session.

Ground truth
------------
Everything here is anchored to one real OpenSSL TLS 1.3 run:

    .../TLS13/100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/

``session_tls13.pcap`` is a byte-for-byte copy of that run's ``traffic.pcap``.
The embedded secret is that session's real ``SERVER_TRAFFIC_SECRET_0`` (32 bytes),
read from its ``keylog.csv``. (In this KeyUpdate-abort run the *server* traffic
secret is the TRAFFIC_SECRET_0 the pcap oracle confirms; ``CLIENT_TRAFFIC_SECRET_0``
does not decrypt any captured application-data record and is therefore NOT used.)

Two invariants make the fixture actually reproduce a hit in the real pipeline
------------------------------------------------------------------------------
1. **N = 1 (a single .msl).** ``engine/candidate_pipeline.py`` sets
   ``MIN_N_FOR_VARIANCE = 3``: with fewer than 3 dumps ``reduce_search_space``
   cannot compute a meaningful cross-dump variance (Welford's population
   variance at n=1 is zero everywhere), so it BYPASSES the variance + alignment
   filters and reduces on Shannon entropy alone. A single random-filled page
   therefore survives reduction and reaches the brute-force grid. Feeding >1
   dump would instead demand a real variance signal we cannot synthesise here.

2. **Stride-8-aligned absolute offset.** ``engine/candidate_grid.py``
   ``iter_region_grid`` snaps candidate offsets to an ABSOLUTE stride grid:
   ``first_offset = ceil(r_start / stride) * stride``, then steps by ``stride``.
   With the default ``stride = 8`` the embedded secret is only ever *tested* if
   its offset in the reference byte stream is a multiple of 8. We embed it at a
   deliberately 8-aligned page offset (``_SECRET_OFFSET``); because the single
   region's page is all-CAPTURED, the ``view="vas"`` offset equals the page
   offset, so the reference-stream offset stays 8-aligned.

The reference-stream coordinate is the ``.msl`` ``view="vas"`` projection
(``MslDumpSource.read_all()`` default): a flattened concatenation of CAPTURED
page runs. For our single 1-page region that is simply the 4096-byte page, so
page offset == vas offset == reference.bin offset.

Self-check (runs before anything is committed)
----------------------------------------------
``main()`` builds the pcap + .msl into a temp dir and drives BOTH producer paths
the web pipeline can take, asserting the same ``confirmed_by == "pcap"`` /
``key_hex == secret`` hit at ``_SECRET_OFFSET`` on each:

 1. N=1 (single .msl) — the reduce->brute-force path::

        tools_pipeline.search_reduce(num_dumps=1)   # == pipeline_runner._run_reduce
        tools_pipeline.brute_force(pcap_path=...)    # == pipeline_runner._run_brute_force

 2. N=2 (the fixture MSL + a byte-identical copy) — the FULL consensus path the
    browser spec actually folds, which prepends the real consensus stage::

        tools_pipeline.consensus(persist_welford=True)  # == pipeline_runner._stage_consensus
        tools_pipeline.search_reduce(num_dumps=2)        # 2 < MIN_N_FOR_VARIANCE => entropy-only
        tools_pipeline.brute_force(pcap_path=...)

The committed ``matched.msl`` / ``session_tls13.pcap`` / ``manifest.json`` are
written ONLY if BOTH assertions pass, so a committed fixture is always one the
real pipeline (N=1 or the N=2 browser path) can reproduce.

Deterministic + re-runnable: the page fill uses a fixed RNG seed and the MSL
UUID/timestamp are held constant, so regenerating produces byte-identical output.

Run from anywhere:

    /path/to/python tests/e2e/fixtures/pcap/generate.py
"""

from __future__ import annotations

import json
import random
import sys
import tempfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/pcap -> repo root
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"

# Make the synthetic-MSL byte-layout builders + shared TLS ground-truth
# importable regardless of cwd.
sys.path.insert(0, str(FIXTURE_DIR))

import generate_msl_fixtures as gm  # noqa: E402
from tls_ground_truth import (  # noqa: E402
    CLIENT_RANDOM,
    SECRETS,
    SOURCE_RUN,
    copy_real_pcap,
    real_pcap_path,
)

# -- Ground truth (real OpenSSL TLS 1.3 run) -------------------------------- #
# The corpus root (and thus SOURCE_RUN / REAL_PCAP) is overridable via
# ``MEMDIVER_TLS_DUMPS_DIR``; only this regeneration reads it — consuming the
# COMMITTED fixture never touches the env. See tests/fixtures/tls_ground_truth.py.
REAL_PCAP = real_pcap_path()

# The TRAFFIC_SECRET_0 the pcap oracle confirms for this capture (see docstring).
SECRET_LABEL = "SERVER_TRAFFIC_SECRET_0"
SECRET_HEX = SECRETS[SECRET_LABEL]
SECRET = bytes.fromhex(SECRET_HEX)

# -- Fixture-shape constants ------------------------------------------------ #
_REGION_BASE = 0x7FFF00000000
_TIMESTAMP_NS = 1_700_000_000_000_000_000
_PAGE_FILL_SEED = 20240823
_SECRET_OFFSET = 512  # 8-aligned page offset (512 % 8 == 0); see invariant #2
_KEY_SIZE = 32
_STRIDE = 8

# Committed outputs.
OUT_PCAP = HERE / "session_tls13.pcap"
OUT_MSL = HERE / "matched.msl"
OUT_MANIFEST = HERE / "manifest.json"


def _build_matched_msl() -> bytes:
    """Return the bytes of an N=1 native .msl embedding SECRET at _SECRET_OFFSET.

    One 1-page all-CAPTURED memory region filled with deterministic random bytes
    (high entropy so the secret survives entropy-only reduction), with SECRET
    overwritten at the 8-aligned page offset.
    """
    if _SECRET_OFFSET % _STRIDE != 0:
        raise AssertionError(f"secret offset {_SECRET_OFFSET} not {_STRIDE}-aligned")

    fill = random.Random(_PAGE_FILL_SEED)
    page = bytearray(fill.getrandbits(8) for _ in range(gm.PAGE_SIZE))
    page[_SECRET_OFFSET:_SECRET_OFFSET + len(SECRET)] = SECRET

    # Deterministic UUIDs: reseed the builder RNG so regeneration is stable.
    gm._RNG = random.Random(42)
    dump_uuid = gm._det_uuid()
    blob = gm._build_file_header(dump_uuid, _TIMESTAMP_NS)
    region_block, _ = gm._build_memory_region(
        base_addr=_REGION_BASE, num_pages=1, page_data=bytes(page),
    )
    blob += region_block
    return blob


def _self_verify(msl_bytes: bytes, pcap_path: Path, work: Path) -> dict:
    """Reproduce the web pipeline reduce->brute_force path; return the hit dict.

    Raises AssertionError if no ``confirmed_by == "pcap"`` hit for SECRET is
    produced — the whole point of the fixture.
    """
    from memdiver.app import tools_pipeline
    from memdiver.app.composition import open_dump

    msl_path = work / "matched.msl"
    msl_path.write_bytes(msl_bytes)

    # 1. The reference byte stream the pipeline reduces + brute-forces over is
    #    the .msl "vas" projection (MslDumpSource.read_all default). Confirm the
    #    secret landed at an 8-aligned offset in THAT coordinate.
    with open_dump(msl_path) as src:
        reference = src.read_all()  # view="vas"
        located = src.find_all(SECRET)  # vas offsets
        readback = src.read_range(_SECRET_OFFSET, len(SECRET))

    if located != [_SECRET_OFFSET]:
        raise AssertionError(
            f"secret located at {located}, expected [{_SECRET_OFFSET}]"
        )
    if readback != SECRET:
        raise AssertionError("read_range did not return the embedded secret")
    if _SECRET_OFFSET % _STRIDE != 0:
        raise AssertionError("secret offset is not stride-aligned in vas view")

    ref_path = work / "reference.bin"
    ref_path.write_bytes(reference)

    # 2. N=1 => reduce_search_space falls back to entropy-only. variance is
    #    ignored past its length, but search_reduce mmaps a real .npy, so write a
    #    zero variance array sized to the reference.
    var_path = work / "variance.npy"
    np.save(var_path, np.zeros(len(reference), dtype=np.float64))

    # 3. search-reduce (== pipeline_runner._run_reduce -> tools_pipeline.search_reduce)
    sr = tools_pipeline.search_reduce(
        variance_path=str(var_path),
        reference_path=str(ref_path),
        num_dumps=1,
        output_dir=str(work / "search_reduce"),
    )
    if not sr["fallback_entropy_only"]:
        raise AssertionError("expected N=1 entropy-only fallback in search-reduce")

    # 4. brute-force through the first-party pcap oracle
    #    (== pipeline_runner._run_brute_force -> tools_pipeline.brute_force).
    bf = tools_pipeline.brute_force(
        candidates_path=sr["candidates_path"],
        reference_path=str(ref_path),
        output_dir=str(work / "brute_force"),
        pcap_path=str(pcap_path),
        tls_client_random=CLIENT_RANDOM,
        key_sizes=(_KEY_SIZE,),
        stride=_STRIDE,
    )

    confirmed = [
        h for h in bf["hits"]
        if h.get("confirmed_by") == "pcap" and h.get("key_hex") == SECRET_HEX
    ]
    if not confirmed:
        raise AssertionError(
            "no confirmed_by=='pcap' hit for the embedded secret; "
            f"got hits={bf['hits']!r}"
        )
    return confirmed[0]


def _self_verify_consensus(msl_bytes: bytes, pcap_path: Path, work: Path) -> dict:
    """Reproduce the *web* pipeline consensus->reduce->brute_force path at N=2.

    ``_self_verify`` above proves the N=1 (single-.msl) reduce->brute-force path.
    The browser spec instead folds the fixture MSL + a byte-identical copy (N=2)
    through the REAL ``tools_pipeline.consensus`` stage first
    (== ``pipeline_runner._stage_consensus``, ``persist_welford=True``). With
    ``2 < MIN_N_FOR_VARIANCE = 3`` consensus's variance is unreliable, so the
    downstream reduce falls back to entropy-only — the exact fallback the browser
    exercises. This drives that producer path and asserts the SAME
    ``confirmed_by == "pcap"`` hit for SECRET at ``_SECRET_OFFSET``.

    Raises AssertionError if consensus's ``reference.bin`` does not carry the
    secret at ``_SECRET_OFFSET`` (coordinate drift — the committed fixture/offset
    would be wrong for the N=2 path) or if no pcap-confirmed hit is produced.
    """
    from memdiver.app import tools_pipeline

    # Two byte-identical dump paths, mirroring the browser (which dedups identical
    # paste paths, so it uses a second copy at a distinct path).
    msl_a = work / "consensus_a.msl"
    msl_b = work / "consensus_b.msl"
    msl_a.write_bytes(msl_bytes)
    msl_b.write_bytes(msl_bytes)

    # 1. Consensus over N=2 (== _stage_consensus): persist_welford=True, default
    #    normalize. Returns reference.bin + variance.npy paths + num_dumps.
    cons = tools_pipeline.consensus(
        dump_paths=[str(msl_a), str(msl_b)],
        output_dir=str(work / "consensus"),
        persist_welford=True,
    )
    if cons["num_dumps"] != 2:
        raise AssertionError(f"expected consensus num_dumps==2, got {cons['num_dumps']}")

    # The consensus reference.bin is the coordinate space reduce/brute-force run
    # over. Confirm the embedded secret survived at the SAME offset the N=1 path
    # and manifest use; if it moved, STOP loudly rather than diverge silently.
    ref_bytes = Path(cons["reference_path"]).read_bytes()
    locations = [
        i for i in range(len(ref_bytes) - len(SECRET) + 1)
        if ref_bytes[i:i + len(SECRET)] == SECRET
    ]
    if locations != [_SECRET_OFFSET]:
        raise AssertionError(
            f"N=2 consensus reference.bin locates secret at {locations}, expected "
            f"[{_SECRET_OFFSET}] -- consensus coordinate drift vs the N=1 fixture"
        )

    # 2. search-reduce (== _stage_reduce -> _run_reduce). N=2 < 3 => entropy-only.
    sr = tools_pipeline.search_reduce(
        variance_path=cons["variance_path"],
        reference_path=cons["reference_path"],
        num_dumps=cons["num_dumps"],
        output_dir=str(work / "consensus_search_reduce"),
    )
    if not sr["fallback_entropy_only"]:
        raise AssertionError("expected N=2 entropy-only fallback in consensus search-reduce")

    # 3. brute-force through the first-party pcap oracle over the consensus ref.
    bf = tools_pipeline.brute_force(
        candidates_path=sr["candidates_path"],
        reference_path=cons["reference_path"],
        output_dir=str(work / "consensus_brute_force"),
        pcap_path=str(pcap_path),
        tls_client_random=CLIENT_RANDOM,
        key_sizes=(_KEY_SIZE,),
        stride=_STRIDE,
    )
    confirmed = [
        h for h in bf["hits"]
        if h.get("confirmed_by") == "pcap" and h.get("key_hex") == SECRET_HEX
    ]
    if not confirmed:
        raise AssertionError(
            "no confirmed_by=='pcap' hit for the embedded secret via the N=2 "
            f"consensus path; got hits={bf['hits']!r}"
        )
    if confirmed[0].get("offset") != _SECRET_OFFSET:
        raise AssertionError(
            f"N=2 consensus hit at offset {confirmed[0].get('offset')}, "
            f"expected {_SECRET_OFFSET}"
        )
    return confirmed[0]


def main() -> None:
    msl_bytes = _build_matched_msl()

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        # copy_real_pcap carries the REAL_PCAP.is_file() guard (SystemExit if the
        # machine-local corpus is absent).
        pcap_tmp = copy_real_pcap(work / "session_tls13.pcap")
        hit = _self_verify(msl_bytes, pcap_tmp, work)
        hit_consensus = _self_verify_consensus(msl_bytes, pcap_tmp, work)

    # Self-check passed — safe to write the committed fixture files.
    copy_real_pcap(OUT_PCAP)
    OUT_MSL.write_bytes(msl_bytes)
    manifest = {
        "secret_hex": SECRET_HEX,
        "secret_label": SECRET_LABEL,
        "offset": _SECRET_OFFSET,
        "client_random": CLIENT_RANDOM,
        "key_size": _KEY_SIZE,
        "stride": _STRIDE,
        "source_run": SOURCE_RUN,
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    print("SELF-VERIFY (N=1 reduce->brute_force) OK -- confirmed pcap-oracle hit:")
    print(json.dumps(hit, indent=2))
    print("SELF-VERIFY (N=2 consensus->reduce->brute_force) OK -- confirmed pcap-oracle hit:")
    print(json.dumps(hit_consensus, indent=2))
    print(f"secret_label = {SECRET_LABEL}")
    print(f"offset = {_SECRET_OFFSET}  (offset % {_STRIDE} == {_SECRET_OFFSET % _STRIDE})")
    for p in (OUT_PCAP, OUT_MSL, OUT_MANIFEST):
        print(f"wrote {p}  ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
