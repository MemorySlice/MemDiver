"""Scan router — run a MemDiver-emitted YARA rule, and SCORE what it found.

Exposes three routes. The first two are two halves of one story; the third is
the same story told about the OTHER thing MemDiver emits:

* ``POST /api/scan/yara`` — the web face of ``analysis.yara_scan``: compile ONE
  rule set (inline text or ``.yar`` files) and scan every supplied dump with
  it, returning a per-dump census.
* ``POST /api/scan/score`` — the web face of ``analysis.score_detector``: take
  those firings, put them beside the key's known-true intervals, and return
  interval precision/recall. Without it a scan yields detector firings with no
  way to judge them, and "matched" is not a synonym for "was right".
* ``POST /api/scan/verify-plugin`` — the web face of
  ``analysis.verify_plugin``: RUN a MemDiver-emitted Volatility3 plugin over N
  dumps, in this process and/or through the operator's own ``vol`` launcher,
  and report which runtime and which RESOLVED framework version answered.

This is the other half of the architect router next door. ``/api/architect/export``
WRITES a signature; this route RUNS one, which is what makes an emitted detector
measurable at all rather than merely publishable.

It is deliberately a router of its own rather than a route on an existing one:

* ``architect`` is on ``EXEMPT_ROUTERS`` in
  ``tests/test_capability_completeness.py`` with the reason "NO APP-LAYER
  PRODUCER". Putting a registered capability behind it would make that coarse
  exemption illegal.
* ``analysis`` is still on the legacy ``{"detail": ...}`` error contract, and
  this route wants the MODERN one: there is no ``try``/``except`` below, so a
  ``CapabilityError`` from the producer or the engine reaches the single global
  handler in ``api/main.py`` and is rendered as ``{error, code, category}``
  with the category's own status.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

# The producer's own defaults, imported rather than re-literalled so this
# route's advertised cap and budget cannot drift from the values the library,
# the CLI and the MCP tool apply.
from memdiver.app.tools_pipeline import (
    DEFAULT_INCLUDE_HITS,
    DEFAULT_INCLUDE_MATCHES,
    VOL3_MAX_HITS,
    VOL3_MODE_AUTO,
    VOL3_SUBPROC_TIMEOUT_S,
)
from memdiver.engine.detector_metrics import DEFAULT_TOLERANCE_BYTES
from memdiver.engine.yara_scan import DEFAULT_MAX_MATCHES, DEFAULT_TIMEOUT_S

logger = logging.getLogger("memdiver.api.routers.scan")

router = APIRouter()


class ScanYaraRequest(BaseModel):
    """Body for ``POST /api/scan/yara``: one rule set, N dumps.

    Supply exactly ONE of ``rule_source`` or ``rule_paths``; the producer
    refuses both (and neither) with INVALID_INPUT, and this model deliberately
    does not pre-empt that with a validator so all four surfaces report the
    mistake in the same words. A precompiled ``.yarc`` is not accepted in any
    form — a compiled rule file is executable libyara bytecode, so loading one
    from a request body would be an arbitrary-behaviour surface.

    ``max_matches`` / ``overlap_bytes`` carry NO ``Field(ge=...)`` constraint,
    unlike ``LocateFieldPairsRequest``'s caps. That is on purpose: the engine
    already refuses ``max_matches <= 0`` (``yara.bad_max_matches``, whose
    message names the ``None`` remedy) and a negative overlap
    (``yara.bad_overlap``), so validating here would answer 422 with FastAPI's
    words where the other three surfaces answer with the engine's. ``None`` on
    ``max_matches`` means "no cap at all", which is a legitimate request for a
    recall measurement and must survive the wire.

    ``include_matches=False`` asks for the COUNT-ONLY census: the same payload
    with each row's ``matches`` list omitted and ``matches_omitted: true`` in
    its place, every count and flag retained. It bounds the RESPONSE, not the
    scan — an unselective rule can fire hundreds of thousands of times per
    dump, each firing carrying up to 512 bytes of ``matched_hex``, and
    ``max_matches`` only ever bounded server-side memory. It is orthogonal to
    ``max_matches`` (see the producer), so a count-only response taken under a
    cap reports a floor and says so in its ``count_only`` diagnostic. A plain
    ``bool`` with the producer's own constant as its default, so the route
    cannot advertise a verbosity the library does not apply.
    """

    dump_paths: List[str]
    rule_source: Optional[str] = None
    rule_paths: Optional[List[str]] = None
    view: Optional[str] = None
    max_matches: Optional[int] = DEFAULT_MAX_MATCHES
    timeout_s: int = DEFAULT_TIMEOUT_S
    overlap_bytes: int = 0
    include_matches: bool = DEFAULT_INCLUDE_MATCHES


@router.post("/yara")
def scan_yara(body: ScanYaraRequest):
    """Compile one YARA rule set and scan N dumps with it.

    Like ``POST /api/pcaps/locate-field``, the paths are READS of files the
    operator chose and are checked for existence by the producer only, matching
    ``POST /api/pipeline/run``; see the localhost trust-model note in
    ``api/main.py``.

    The compute is delegated to
    :func:`memdiver.app.tools_pipeline.scan_yara_rule` — the same producer the
    CLI ``scan-yara`` command, the MCP ``scan_yara_rule`` tool and
    ``memdiver.services`` route to, so the four surfaces cannot drift. Every
    failure (both rule forms, a bad rule, a missing path, a locked container, a
    non-positive match cap) surfaces as its ``CapabilityError``, translated by
    the app's global handler.

    Read the response's ``verdict`` before any count: only ``"clean"`` is an
    absence. ``"inconclusive"`` (nothing matched, but a scan timed out or
    errored) and ``"not_scanned"`` claim nothing at all.
    """
    from memdiver.app.tools_pipeline import scan_yara_rule

    return scan_yara_rule(
        dump_paths=body.dump_paths,
        rule_source=body.rule_source,
        rule_paths=body.rule_paths,
        view=body.view,
        max_matches=body.max_matches,
        timeout_s=body.timeout_s,
        overlap_bytes=body.overlap_bytes,
        include_matches=body.include_matches,
    )


class ScoreDetectorRequest(BaseModel):
    """Body for ``POST /api/scan/score``: firings in, precision/recall out.

    Supply exactly ONE intake — ``matches`` (+ ``truths`` and the optional
    ``detector`` / ``dump`` / ``truth_sources`` labels) for a single
    (detector, dump) pair, or ``rows`` for N pre-grouped rows. The producer
    refuses both (and neither) with INVALID_INPUT, and this model deliberately
    does not pre-empt that with a validator so all four surfaces report the
    mistake in the same words.

    ``matches`` / ``truths`` / ``rows`` are typed as loose objects rather than
    as nested Pydantic models, for the same reason ``ScanYaraRequest``'s caps
    carry no ``Field(ge=...)``: the producer owns the geometry validation. It
    refuses a firing with no ``offset`` — and it must, because the metrics
    engine reads its inputs by ``getattr`` and coerces a missing one to ``0``,
    so a forgotten field becomes a plausible firing at the start of the dump
    rather than an error. Validating here would answer 422 in FastAPI's words
    where the other three surfaces answer in the producer's, and the words are
    the part worth keeping.
    """

    matches: Optional[List[Dict[str, Any]]] = None
    truths: Optional[List[Dict[str, Any]]] = None
    detector: Optional[str] = None
    dump: Optional[str] = None
    truth_sources: Optional[List[str]] = None
    rows: Optional[List[Dict[str, Any]]] = None
    tolerance_bytes: int = DEFAULT_TOLERANCE_BYTES


@router.post("/score")
def score_detector(body: ScoreDetectorRequest):
    """Score detector firings against known-true key intervals.

    The other half of ``POST /api/scan/yara`` above: feed this route that
    route's ``dumps[].scan.matches`` together with the intervals the key is
    known to occupy, and it answers how much of the detector's output was
    right. No dump is opened — everything arrives in the body — so unlike its
    neighbour this route touches no path and needs no key material.

    The compute is delegated to
    :func:`memdiver.app.tools_pipeline.score_detector_matches` — the same
    producer the CLI ``score-detector`` command, the MCP
    ``score_detector_matches`` tool and ``memdiver.services`` route to, so the
    four surfaces cannot drift. Every failure (both intakes, neither, a
    negative tolerance, a firing with no byte position) surfaces as its
    ``CapabilityError``, translated by the app's global handler.

    Read the response's ``verdict`` before any number: only ``"scored"`` is a
    measurement. ``"no_truths"`` means nothing was scorable and ``report`` is
    ``null``; ``"no_matches"`` is the one zero that IS real — the detector
    fired on none of the keys there were to find.
    """
    from memdiver.app.tools_pipeline import score_detector_matches

    return score_detector_matches(
        matches=body.matches,
        truths=body.truths,
        detector=body.detector,
        dump=body.dump,
        truth_sources=body.truth_sources,
        rows=body.rows,
        tolerance_bytes=body.tolerance_bytes,
    )


class VerifyPluginRequest(BaseModel):
    """Body for ``POST /api/scan/verify-plugin``: one emitted plugin, N dumps.

    Supply exactly ONE of ``plugin_source`` or ``plugin_path``; the producer
    refuses both (and neither) with INVALID_INPUT, and this model deliberately
    does not pre-empt that with a validator so all four surfaces report the
    mistake in the same words.

    ``vol_bin`` / ``vol_python`` are the reason this route can serve the whole
    capability. Launcher selection was previously env-var-only
    (``MEMDIVER_VOL3_BIN`` / ``MEMDIVER_VOL3_PYTHON``), and an environment
    variable is not something an HTTP body can set — so "by default use the
    PyPI volatility3, but let me point at my own tool" was reachable from the
    shell alone. Both fields BEAT the env vars.

    No field carries a ``Field(ge=...)`` constraint, for the reason
    ``ScanYaraRequest``'s caps do not: the producer owns the validation (an
    unknown ``mode``, a bad ``key_hex``, an empty ``dump_paths``), so
    validating here would answer 422 in FastAPI's words where the other three
    surfaces answer in the producer's.

    ``pid`` is passed through to the plugin's ``--pid`` and is **explicitly
    unproven** — narrowing needs a kernel image plus a matching ISF, which
    neither this repo nor the machine it was developed on has. A diagnostic
    says so on every run that supplies one.
    """

    dump_paths: List[str]
    plugin_source: Optional[str] = None
    plugin_path: Optional[str] = None
    mode: str = VOL3_MODE_AUTO
    view: Optional[str] = None
    expected_offset: Optional[int] = None
    key_hex: Optional[str] = None
    pid: Optional[int] = None
    vol_bin: Optional[str] = None
    vol_python: Optional[str] = None
    timeout_s: int = VOL3_SUBPROC_TIMEOUT_S
    max_hits: int = VOL3_MAX_HITS
    include_hits: bool = DEFAULT_INCLUDE_HITS


@router.post("/verify-plugin")
def verify_plugin(body: VerifyPluginRequest):
    """Run a MemDiver-emitted Volatility3 plugin over N dumps.

    The third route on this router, and the one that finishes the emit → run
    loop: ``/api/architect/export`` WRITES a plugin, ``POST /api/scan/yara``
    runs the YARA half of an export, and this runs the Volatility3 half —
    either in this process (against the ``volatility3`` MemDiver imports) or
    through the operator's own ``vol`` launcher, which is how a plugin is
    actually used and frequently a different framework version.

    Like its neighbours the paths are READS of files the operator chose and are
    checked for existence by the producer only; see the localhost trust-model
    note in ``api/main.py``.

    The compute is delegated to
    :func:`memdiver.app.tools_pipeline.verify_vol3_plugin` — the same producer
    the CLI ``verify-plugin`` command, the MCP ``verify_vol3_plugin`` tool and
    ``memdiver.services`` route to, so the four surfaces cannot drift. Every
    failure (both plugin forms, an unknown mode, a missing runtime, a locked
    container, a plugin that will not import) surfaces as its
    ``CapabilityError``, translated by the app's global handler.

    Read the response's ``verdict`` before any count: only ``"no_hit"`` is an
    absence. ``"inconclusive"`` and ``"not_run"`` claim nothing at all — and
    ``"not_run"`` is in particular what ``mode="subprocess"`` over an ``.msl``
    returns, because ``vol`` would scan the CONTAINER rather than the view — a
    measured offset skew of the container's header size (1080 bytes on the
    ground-truth import). Then read ``runtime`` and each row's
    ``framework_version``: a verification that does not name the framework that
    produced it cannot be reproduced.
    """
    from memdiver.app.tools_pipeline import verify_vol3_plugin

    return verify_vol3_plugin(
        dump_paths=body.dump_paths,
        plugin_source=body.plugin_source,
        plugin_path=body.plugin_path,
        mode=body.mode,
        view=body.view,
        expected_offset=body.expected_offset,
        key_hex=body.key_hex,
        pid=body.pid,
        vol_bin=body.vol_bin,
        vol_python=body.vol_python,
        timeout_s=body.timeout_s,
        max_hits=body.max_hits,
        include_hits=body.include_hits,
    )
