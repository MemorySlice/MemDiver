"""Pydantic v2 request/response models for the MemDiver API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from memdiver.app.tools_consensus import (
    DEFAULT_REGIONS_PER_PAGE,
    MAX_REGIONS_PER_PAGE,
)
from memdiver.app.tools_pipeline import DEFAULT_MAX_RETURNED_REGIONS
from memdiver.core.input_schemas import OUTPUT_FORMATS
from memdiver.engine.key_location import (
    DEFAULT_KEY_CONTEXT,
    DEFAULT_MAX_KEY_OFFSETS,
)


class ScanRequest(BaseModel):
    """Request body for dataset scanning."""

    root: str
    keylog_filename: str = "keylog.csv"
    protocols: list[str] | None = None


class AnalyzeRequestAPI(BaseModel):
    """Request body for library analysis."""

    library_dirs: list[str]
    phase: str
    protocol_version: str
    keylog_filename: str = "keylog.csv"
    template_name: str = "Auto-detect"
    max_runs: int = 10
    normalize: bool = False
    expand_keys: bool = True
    algorithms: list[str] | None = None


class KeyMaterialFields(BaseModel):
    """Mixin of optional decryption fields for encrypted ``.msl`` inputs.

    Same shape as ``POST /api/inspect/tag-status``: ``passphrase`` (utf-8),
    ``key_hex`` (raw symmetric key, hex), ``kem_key_hex`` (KEM private key,
    hex). All optional — omit for plaintext dumps (spec §10).

    WIRE-FIELD COLLISION, read before adding a field. On this wire ``key_hex``
    means THE CONTAINER DECRYPTION KEY and nothing else. The key-location
    requests below carry a *TLS secret to search for*, which is a completely
    different value with the same natural name — so they spell it
    ``secret_hex`` and the route maps it to the producer's ``key_hex=``
    parameter. Reusing ``key_hex`` for both would let one field decrypt the
    container in one request and be searched for as a needle in the next.
    """

    passphrase: str | None = None
    key_hex: str | None = None
    kem_key_hex: str | None = None


class ConsensusRequest(KeyMaterialFields):
    """Request body for consensus matrix computation."""

    dump_paths: list[str]
    normalize: bool = False


class AlignedWindowKey(KeyMaterialFields):
    """Decryption material for ONE dump of an aligned-window request.

    The window's N dumps are not a single keyed unit: a corpus routinely mixes
    plaintext captures with containers encrypted under different keys, and a
    flat ``key_hex`` for the whole request would silently try dump A's key on
    dump B. Each entry names its ``dump_path`` and carries the same three
    ``KeyMaterialFields`` every other route accepts.
    """

    dump_path: str


class AlignedWindowRequest(BaseModel):
    """Request body for ``POST /api/analysis/consensus/aligned-window``.

    POST rather than GET for two reasons that are not style: N dump paths plus
    N key triples do not fit a query string, and key material must stay out of
    access logs, shell history and ``Referer`` headers.

    Exactly ONE of ``consensus_id`` (a build registered by ``POST /consensus``)
    or ``dump_paths`` (build one now, or serve the labelled no-consensus
    window) — neither and both are 400s, because "which correspondence is this
    window in" has to have exactly one answer.

    The anchor dump is ``anchor_path``, NOT ``dump_path``. It is spelled that
    way because it is the ANCHOR — the one dump whose coordinate the request is
    phrased in — and because ``dump_paths`` (the whole set) already lives on
    this model: two fields one character apart meaning "the anchor" and "every
    dump" is a footgun, and a request that misspells one as the other would
    silently fall through to a slab anchor at offset 0 and answer a different
    question in a different coordinate. It also matches the producer kwarg
    (``aligned_window_result(anchor_path=...)``). There is deliberately NO
    ``dump_path`` alias: an unknown field is dropped by pydantic, so an alias
    would re-open exactly the ambiguity the rename closes.
    """

    consensus_id: str | None = None
    dump_paths: list[str] | None = None
    #: ``"dump"`` reads ``anchor_path`` + ``view`` + ``offset``; ``"slab"``
    #: reads ``slab_offset`` and needs no dump. Each REQUIRES its own field —
    #: the route 400s rather than defaulting, see ``_aligned_window_anchor``.
    anchor: Literal["dump", "slab"] = "dump"
    #: The anchor dump. Note the RESPONSE still spells its anchor block's path
    #: ``anchor.dump_path``; only this request field carries the anchor name.
    anchor_path: str | None = None
    view: Literal["va", "vas", "raw"] = "va"
    offset: int = 0
    slab_offset: int | None = None
    length: int = 1024
    #: Subset of the build to return, as dump paths or build-order indices.
    dumps: list[str | int] | None = None
    normalize: bool = False
    classify: bool = True
    include_bytes: bool = True
    keys: list[AlignedWindowKey] = Field(default_factory=list)


class ConsensusRegionsRequest(BaseModel):
    """Request body for ``POST /api/analysis/consensus/regions``.

    Every occurrence of a consensus class, paginated and JUMPABLE — the list
    behind "show me every key candidate", where clicking a row scrolls the hex
    viewer to that byte.

    POST, not GET, for the two reasons :class:`AlignedWindowRequest` gives and
    they apply verbatim: N key triples do not fit a query string, and key
    material must stay out of access logs, shell history and ``Referer``. The
    keys are not decoration — resolving a ``"vas"`` anchor offset means OPENING
    (and therefore decrypting) the anchor container.

    Exactly ONE of ``consensus_id`` / ``dump_paths``, for the same reason:
    "which correspondence are these regions in" has to have exactly one answer.

    ``classes`` omitted is the NON-INVARIANT UNION, not "every class" and not
    "key_candidate". Real key material is class-mixed, so a per-class query
    shatters a real secret into shards; ``"non_invariant"`` names the union
    explicitly. See ``app.tools_consensus.class_regions_from_vector``.
    """

    consensus_id: str | None = None
    dump_paths: list[str] | None = None
    #: Class names ("invariant"/"structural"/"pointer"/"key_candidate"), raw
    #: integer codes as strings, or the ``"non_invariant"`` union alias.
    classes: list[str] | None = None
    min_length: int = 8
    max_length: int = 0
    #: Row order. ``"offset"`` is address order; the length sorts answer "show me
    #: the biggest key candidates first", which is how an analyst who knows a
    #: secret's size actually looks for it.
    sort: Literal["offset", "length_desc", "length_asc"] = "offset"
    #: EXCLUSIVE cursor — the previous page's ``next_after``. Its UNIT follows
    #: ``sort``: an aligned-space offset for ``"offset"``, a rank index for the
    #: sorts. OPAQUE to clients, which only ever hand it back or compare it
    #: to ``-1``; nothing may do arithmetic on it.
    after: int = -1
    limit: int = Field(DEFAULT_REGIONS_PER_PAGE, ge=1, le=MAX_REGIONS_PER_PAGE)
    #: The dump whose coordinate the jump offsets are expressed in. Spelled
    #: ``anchor_path`` for the reason :class:`AlignedWindowRequest` documents.
    anchor_path: str | None = None
    anchor_view: Literal["va", "vas", "raw"] = "va"
    include_anchor_offsets: bool = True
    normalize: bool = False
    keys: list[AlignedWindowKey] = Field(default_factory=list)


class AnalysisCandidatesRequest(KeyMaterialFields):
    """Request body for the exploratory candidate search (no oracle, no pcap).

    Mirrors ``app.tools_pipeline.analyze_candidates`` 1:1 so the web surface
    cannot express less than the CLI or MCP one. ``min_variance`` stays
    ``None`` by default on purpose: the producer resolves it against
    ``classes`` (3000 with no class named, 0 with one), and a wire default of
    3000 here would silently re-impose the KEY_CANDIDATE floor on every
    multi-class query the UI sends.
    """

    dump_paths: list[str]
    classes: list[str] | None = None
    min_variance: float | None = None
    min_region: int = 16
    max_region: int = 0
    alignment: int = 8
    block_size: int = 32
    density_threshold: float = 0.5
    entropy_window: int = 32
    entropy_threshold: float = 4.5
    order: str = "rank"
    max_returned: int = DEFAULT_MAX_RETURNED_REGIONS
    normalize: bool = False
    project_id: str = ""


class KeySecretFields(KeyMaterialFields):
    """The three mutually-exclusive spellings of "here is the secret".

    ``secret_hex`` is the producer's ``key_hex`` parameter renamed for the wire:
    see the collision note on :class:`KeyMaterialFields`. The inherited
    ``key_hex`` keeps its container-decryption meaning, so one request can both
    decrypt an encrypted ``.msl`` and search it for a secret.

    Exactly one of the three must be supplied. The check is NOT duplicated here
    as a validator: the producer owns it, so the CLI, MCP and library surfaces
    get the identical error, and a 400 out of the app's global
    ``CapabilityError`` handler is exactly what a 422 from here would have been.
    """

    secret_hex: str = ""
    keylog_line: str = ""
    secret: dict | None = None


class LocateKeyRequest(KeySecretFields):
    """Request body for ``POST /api/analysis/locate-key``.

    Mirrors ``app.tools_pipeline.locate_key`` 1:1. ``dump_paths`` may hold a
    SINGLE dump — locating a key in one dump is a complete answer, unlike every
    other N-dump route.
    """

    dump_paths: list[str]
    view: str | None = None
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS


class KeyPatternRequest(KeySecretFields):
    """Request body for ``POST /api/analysis/key-pattern``.

    Two deliberate per-surface default divergences from the producer, of the
    documented ``order`` kind (``"offset"`` in the producer, ``"rank"`` on the
    surfaces):

    * ``format`` is ``"yara"`` here, not the producer's ``"volatility3"``.
    * ``include_window_hex`` defaults to TRUE here alone. The web UI renders the
      per-dump windows in ``CrossLibraryHex``, which needs the actual bytes; the
      CLI/MCP/library callers do not and should not pay for them.
    """

    dump_paths: list[str]
    context: int = DEFAULT_KEY_CONTEXT
    format: str = "yara"
    name: str = "memdiver_key_pattern"
    min_static_ratio: float = 0.3
    view: str | None = None
    output_dir: str | None = None
    include_window_hex: bool = True
    max_offsets: int = DEFAULT_MAX_KEY_OFFSETS


class AnalyzeFileRequest(KeyMaterialFields):
    """Request body for single-file analysis."""

    dump_path: str
    algorithms: list[str] = ["entropy_scan", "pattern_match", "structure_scan"]
    user_regex: str | None = None
    custom_patterns: list[dict] | None = None


class ConvergenceRequest(BaseModel):
    """Request body for convergence sweep analysis."""

    dump_paths: list[str]
    n_values: list[int] | None = None
    normalize: bool = False
    max_fp: int = 0


class VerifyKeyRequest(KeyMaterialFields):
    """Request body for candidate key decryption verification."""

    dump_path: str
    offset: int
    length: int = 32
    ciphertext_hex: str
    iv_hex: str | None = None
    nonce_hex: str | None = None
    aad_hex: str | None = None
    tag_hex: str | None = None
    cipher: str = "AES-256-CBC"


class AutoExportRequest(KeyMaterialFields):
    """Request body for auto-detect key region and export."""

    dump_paths: list[str]
    format: str = "volatility3"
    name: str = "memdiver_pattern"
    align: bool = True
    context: int = 32


class ManualExportRequest(KeyMaterialFields):
    """Request body for exporting a pattern from a caller-supplied region.

    The manual counterpart to :class:`AutoExportRequest`: the caller already
    knows WHERE the key lives (from ``/api/analysis/candidates``, from a
    previous run, or from a reverse-engineering session) and hands the region
    over explicitly, so there is no consensus pass and no ``align`` / ``context``
    knob to turn — those only mean something while the region is still being
    searched for.

    ``offset`` is interpreted in the same space MemDiver presents offsets in
    (memory-relative for ``.msl`` inputs, raw-file for ``.dump``), because the
    producer reads through each dump's memory projection. ``min_static_ratio``
    is exposed here — unlike on the auto route — because on this path the user
    chose the region and is the one who has to decide how much of it must be
    invariant for a usable signature.

    Deliberately NO ``output_dir``: like the sibling ``/auto-export`` route this
    returns the rendered pattern in the response body rather than writing it to
    an arbitrary server-side path.
    """

    dump_paths: list[str]
    offset: int
    length: int
    format: str = "volatility3"
    name: str = "memdiver_pattern"
    min_static_ratio: float = 0.3


class ExportKeylogRequest(BaseModel):
    """Request body for Wireshark NSS key-log export from recovered secrets.

    ``secrets`` is a list of ``{secret_type, client_random, secret}`` dicts
    (``client_random`` / ``secret`` are hex strings). ``output_path`` is an
    optional server-side path to also write the key log to.
    """

    secrets: list[dict]
    output_path: str | None = None


class BatchJobDTO(BaseModel):
    """JSON-friendly DTO for one batch job.

    Mirrors the fields of ``core.input_schemas.AnalyzeRequest`` but with
    ``library_dirs: list[str]`` instead of ``list[Path]`` so it
    serializes cleanly across the wire and across the multiprocessing
    queue boundary. The worker (``app.pipeline.batch_task_runner.run_batch``)
    re-hydrates each DTO into a real ``AnalyzeRequest``, which is the
    point at which dataclass __post_init__ validates the directories
    exist.
    """

    library_dirs: list[str] = Field(..., min_length=1)
    phase: str = Field(..., min_length=1)
    protocol_version: str = Field(..., min_length=1)
    keylog_filename: str = "keylog.csv"
    template_name: str = "Auto-detect"
    max_runs: int = Field(default=10, ge=1)
    normalize: bool = False
    expand_keys: bool = True
    algorithms: list[str] | None = None


class BatchRunRequest(BaseModel):
    """Request body for ``POST /api/analysis/batch``."""

    jobs: list[BatchJobDTO] = Field(..., min_length=1)
    output_format: str = "json"
    workers: int = Field(default=1, ge=1, le=32)

    @field_validator("output_format")
    @classmethod
    def _validate_output_format(cls, v: str) -> str:
        """Reject unknown formats at the wire boundary (HTTP 422) instead of
        deferring to an async worker failure. Shares ``OUTPUT_FORMATS`` with
        ``core.input_schemas.BatchRequest`` so the two cannot drift."""
        if v not in OUTPUT_FORMATS:
            raise ValueError(f"output_format {v!r} not in {set(OUTPUT_FORMATS)}")
        return v


class BatchRunResponse(BaseModel):
    """Response for a freshly-submitted batch task."""

    task_id: str
    status: str


class AnalysisRunResponse(BaseModel):
    """Response for a freshly-submitted ``run`` / ``run-file`` analysis task.

    Both endpoints now dispatch the GIL-bound algorithm work onto the
    TaskManager's ProcessPool (mirroring ``POST /api/analysis/batch`` and
    the pipeline endpoint) instead of blocking the request thread. The
    caller subscribes to ``/ws/tasks/{task_id}`` for progress and fetches
    the full ``AnalysisResult`` from the ``analysis_result`` artifact on
    completion.
    """

    task_id: str
    status: str
