"""In-process registry for uploaded BYO decryption oracles.

The pipeline's web UI needs a small, stateful place to remember:

* which oracle files have been uploaded
* the sha256 hash observed at upload time (so an ``/arm`` confirmation
  can catch tampering between display and arm)
* whether the oracle has been *armed* (a user-intent confirmation;
  running an unarmed oracle returns 409)
* the detected *shape* (Shape 1 stateless vs Shape 2 stateful factory)

The registry never itself *executes* an oracle. Every endpoint that
runs one loads it via :func:`engine.oracle.load_oracle`, which performs
its own sha256 re-hash + safe-path checks, so the registry is only a
metadata cache — a compromised entry cannot bypass the runtime guard.

Security defaults (see the plan's "Security hardening" section):

* The on-disk oracle file is chmod-ed to ``0o600`` at upload.
* Any co-located ``__pycache__/`` directory is purged before handing
  the path to :func:`load_oracle` so stale bytecode cannot shadow the
  freshly-written source.
* ``sys.dont_write_bytecode = True`` is set at registry construction
  time so the detection probe itself doesn't emit a new cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from memdiver.app.oracle_autoconfig import (
    load_example_automation,
    split_reserved,
)
from memdiver.app.oracle_smoke_test import compose_smoke_samples
from memdiver.core.artifact_util import atomic_write_text
from memdiver.engine.oracle import (
    OracleBuildError,
    OracleLoadError,
    _purge_pycache,
    load_oracle,
    load_oracle_config,
    validate_oracle_sandboxed,
)

logger = logging.getLogger("memdiver.api.services.oracle_registry")

_HEAD_LINES_MAX = 50


class OracleRegistryError(Exception):
    """Base class for registry validation failures."""


class OracleNotFound(OracleRegistryError):
    """The requested oracle id is unknown."""


class OracleNotArmed(OracleRegistryError):
    """The oracle was found but has not been armed for execution."""


class OracleShaMismatch(OracleRegistryError):
    """Arm request supplied a sha256 that no longer matches the file."""


class OracleDisabled(OracleRegistryError):
    """The registry is not configured (no ``MEMDIVER_ORACLE_DIR`` set)."""


class OracleConfigInvalid(OracleRegistryError):
    """``arm()`` replayed the load with the real config and it failed.

    Distinct from the upload-time failures because the fault is the *config*,
    not the file: the same oracle arms fine once the user fixes a value. Maps
    to 400 through the router's generic ``OracleRegistryError`` branch.
    """


@dataclass
class OracleEntry:
    """Metadata about a registered oracle file."""

    oracle_id: str
    filename: str
    path: Path
    sha256: str
    size: int
    shape: int  # 1 or 2
    head_lines: List[str]
    uploaded_at: float = field(default_factory=time.time)
    armed: bool = False
    description: Optional[str] = None
    # The oracle's own parameters (Shape 2 only). Supplied at upload/load or
    # filled in afterwards from the UI form, and confirmed at arm() — which is
    # where it is first replayed against the real oracle. A config naming a
    # filesystem path is security-relevant, so it belongs behind the same
    # user-intent gate that already guards execution.
    config: Dict[str, Any] = field(default_factory=dict)
    # When this entry was last armed, and whether that happened in an EARLIER
    # process. Arming never survives a restart (see _rehydrate), but silently
    # presenting a restored oracle as never-armed reads as "my work is gone";
    # ``previously_armed`` lets the UI say "armed in a previous session --
    # re-arm to run" instead.
    armed_at: Optional[float] = None
    previously_armed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.oracle_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "size": self.size,
            "shape": self.shape,
            "head_lines": list(self.head_lines),
            "uploaded_at": self.uploaded_at,
            "armed": self.armed,
            "previously_armed": self.previously_armed,
            "description": self.description,
            "config": dict(self.config),
        }


_SIDECAR_SCHEMA = 1


def _sidecar_path(oracle_path: Path) -> Path:
    """The metadata file that sits beside ``<uuid>.py`` as ``<uuid>.json``."""
    return oracle_path.with_suffix(".json")


def _entry_to_sidecar(entry: OracleEntry) -> Dict[str, Any]:
    """Serialise the entry metadata that must outlive this process.

    ``head_lines`` is deliberately NOT stored: it is cheap to recompute from
    the file and a stored copy could disagree with the bytes on disk.

    ``shape`` IS stored, and that is load-bearing. Re-deriving it on rehydrate
    would mean calling :func:`_detect_shape`, which *imports the user module*
    -- executing every stored oracle's top level at server boot, with no user
    present and no sandbox probe. A stored shape can only ever mislabel a
    badge; :func:`load_oracle` re-derives the real shape (and re-hashes, and
    re-checks the safe path) every time the oracle is actually run.
    """
    return {
        "schema": _SIDECAR_SCHEMA,
        "oracle_id": entry.oracle_id,
        "filename": entry.filename,
        "description": entry.description,
        "sha256": entry.sha256,
        "size": entry.size,
        "shape": entry.shape,
        "uploaded_at": entry.uploaded_at,
        "config": dict(entry.config),
        "armed_at": entry.armed_at,
    }


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _detect_shape(path: Path) -> int:
    """Return 1 or 2 for Shape 1 / Shape 2, or raise OracleLoadError.

    Purely static: imports the user module (no bytecode cache) and
    inspects which top-level symbol is present. Does NOT invoke
    ``build_oracle`` itself, so Shape 2 oracles that need config (e.g.
    the gocryptfs example which requires a ``sample_ciphertext``
    parameter) are still detected correctly.

    Note: import alone runs the top-level of the module, so a user
    oracle that performs expensive work at import time will pay that
    cost here. The example oracles are all cheap.
    """
    import importlib.util

    from memdiver.engine.oracle import OracleLoadError, _assert_safe_path

    _purge_pycache(path)
    _assert_safe_path(path)
    spec = importlib.util.spec_from_file_location("memdiver_oracle_probe", path)
    if spec is None or spec.loader is None:
        raise OracleLoadError(f"cannot create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise OracleLoadError(f"failed to import oracle {path}: {exc}") from exc
    if callable(getattr(module, "build_oracle", None)):
        return 2
    if callable(getattr(module, "verify", None)):
        return 1
    raise OracleLoadError(
        f"{path}: must export verify(candidate) -> bool or "
        f"build_oracle(config) -> Oracle"
    )


def _example_config_template(
    path: Path,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Parse the sibling ``<stem>.toml``: its config, and which keys are holes.

    A Shape-2 example is useless without its parameters, and the bundled
    ``.toml`` is the authoritative statement of which keys it wants — so it is
    surfaced as a *template* the UI can render as a prefilled form instead of
    making the user read the example's docstring.

    Two things the raw file says are NOT config, and both are separated out
    here rather than left for the UI to re-derive:

    * The reserved ``[memdiver]`` table is memdiver's own automation metadata
      (see :mod:`memdiver.app.oracle_autoconfig`). Left in, the form would
      render it as a config row and submit it to ``build_oracle``, which never
      asked for it.
    * A template *value* may be a hint rather than an answer —
      ``gocryptfs.toml``'s ``/absolute/path/to/your/...`` is a shape, not a
      path. Nothing here rewrites it (expanding or blanking it would hide what
      the example is asking for), so the second half of the return value names
      those keys outright; guessing from the value alone is what made the old
      ``${MEMDIVER_FIXTURE_ROOT}`` spelling load-bearing.

    Parsed with :func:`engine.oracle.load_oracle_config`, the same loader the
    CLI's ``--oracle-config`` uses, so the two can never disagree on syntax.
    """
    toml_path = path.with_suffix(".toml")
    if not toml_path.is_file():
        return None, []
    try:
        template = load_oracle_config(toml_path)
    except (OracleLoadError, ValueError) as exc:
        # A malformed bundled template must not blank the whole Examples tab.
        logger.warning("example config %s failed to parse: %s", toml_path.name, exc)
        return None, []
    config, reserved = split_reserved(template)
    return config, _placeholder_keys(config, reserved)


def _placeholder_keys(
    config: Dict[str, Any], reserved: Dict[str, Any]
) -> List[str]:
    """Name every template key that is a question rather than an answer.

    The union of two independent signals, because neither alone is enough: a
    third-party example may ship a ``${VAR}`` and no reserved table, while a
    bundled one may declare an autofill rule for a value that looks like an
    ordinary path. Sorted so the payload is stable between identical calls.
    """
    autofill = reserved.get("autofill")
    keys = set(autofill) if isinstance(autofill, dict) else set()
    keys.update(
        key
        for key, value in config.items()
        if isinstance(value, str) and _PLACEHOLDER_RE.search(value)
    )
    return sorted(keys)


def _read_head(path: Path, max_lines: int = _HEAD_LINES_MAX) -> List[str]:
    """Return the first ``max_lines`` lines of ``path`` as strings."""
    out: List[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= max_lines:
                break
            out.append(line.rstrip("\n"))
    return out


def _assert_safe_id(oracle_id: str) -> None:
    if not oracle_id:
        raise OracleRegistryError("oracle_id must be non-empty")
    if oracle_id != Path(oracle_id).name or "/" in oracle_id or os.sep in oracle_id:
        raise OracleRegistryError(f"unsafe oracle_id: {oracle_id!r}")
    if oracle_id.startswith(".") or oracle_id in (".", ".."):
        raise OracleRegistryError(f"unsafe oracle_id: {oracle_id!r}")


# Deliberately narrow: only the exact ``${NAME}`` form. A bare ``$`` is a legal
# character in a POSIX path (``/tmp/a$b`` is a real filename, not a template),
# and the shell's ``${VAR:-default}`` / ``$VAR`` spellings appear nowhere in
# this repo's templates — so widening the pattern would only buy false
# positives on paths users legitimately own.
_PLACEHOLDER_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def _find_unexpanded_placeholder(
    config: Dict[str, Any],
) -> Optional[Tuple[str, str]]:
    """Return ``(key, placeholder_text)`` for the first unexpanded value.

    Top-level string values ONLY. Oracle configs are flat ``key = value`` TOML
    tables (see ``docs/oracle/examples/*.toml``), so a recursive walker would
    be machinery with no input to chew on — and it would have to invent an
    answer for what "the key" means inside a nested list, which is exactly the
    part of the message that has to stay actionable.

    Iterates ``sorted(config.items())`` so a config with two placeholders
    always names the same one; a message that changes between identical runs
    is a message users stop trusting.
    """
    for key, value in sorted(config.items()):
        if not isinstance(value, str):
            continue
        match = _PLACEHOLDER_RE.search(value)
        if match is not None:
            return key, match.group(0)
    return None


def _reject_unexpanded_placeholders(
    config: Dict[str, Any], *, filename: str
) -> None:
    """Raise if *config* still carries a template placeholder.

    Nothing in this repo expands ``${VAR}`` in an oracle config, so a template
    that still carries one reaches the filesystem verbatim and used to surface
    as ``FileNotFoundError(2, 'No such file or directory')``: true, but it
    never said the value was still a placeholder, so the user had no way to
    tell "I typed the path wrong" from "I never typed a path at all". Third-
    party examples are the live case — the bundled ``gocryptfs.toml`` now
    spells its hole as prose and declares it in ``config_placeholders``
    instead (see :func:`_example_config_template`).
    """
    found = _find_unexpanded_placeholder(config)
    if found is None:
        return
    key, placeholder = found
    raise OracleConfigInvalid(
        f"oracle {filename}: config value for {key!r} still contains the "
        f"placeholder {placeholder}; replace it with a real absolute path on "
        f"this machine (nothing expands environment variables here)."
    )


def _describe_config_keys(config: Dict[str, Any]) -> str:
    """Describe which keys were supplied, for an error message's parenthetical.

    Spelled as ``config keys: a, b`` rather than a bare ``a, b`` because the
    bare form read as an accusation — a user seeing ``(sample_ciphertext)``
    took it to mean *that key* was the fault, when it only ever meant "these
    are the keys you sent".
    """
    if not config:
        return "no config values supplied"
    return "config keys: " + ", ".join(sorted(config))


def _grade_samples(
    verify: Callable[[bytes], bool],
    samples: Sequence[bytes],
) -> Dict[str, Any]:
    """Run ``verify`` over ``samples`` and tally the outcome.

    The grading half of :meth:`OracleRegistry.dry_run`, lifted out verbatim so
    :meth:`OracleRegistry.smoke_test` grades identically rather than growing a
    second, subtly different loop.

    Returns every key ``dry_run`` reports except ``oracle_id``, in the same
    order, so a caller can splice it back in with
    ``{"oracle_id": ..., **_grade_samples(...)}`` and keep the serialized
    response byte-identical.

    Note the ``per_call_us_avg`` arithmetic: ``t_total`` accumulates only
    non-erroring calls while the divisor subtracts ``errors``, and an
    all-error run clamps the divisor to 1 and reports ``0.0``. That is the
    pinned contract, quirk and all -- this function must not "fix" it.
    """
    results: List[Dict[str, Any]] = []
    passes = 0
    fails = 0
    errors = 0
    t_total = 0.0
    for idx, sample in enumerate(samples):
        t0 = time.monotonic()
        try:
            ok = bool(verify(sample))
        except Exception as exc:  # noqa: BLE001
            errors += 1
            results.append({
                "index": idx,
                "ok": False,
                "error": repr(exc),
            })
            continue
        dt = (time.monotonic() - t0) * 1_000_000
        t_total += dt
        if ok:
            passes += 1
        else:
            fails += 1
        results.append({
            "index": idx,
            "ok": ok,
            "duration_us": round(dt, 2),
        })
    return {
        "samples": len(samples),
        "passes": passes,
        "fails": fails,
        "errors": errors,
        "per_call_us_avg": round(t_total / max(1, len(samples) - errors), 2),
        "results": results,
    }


def _smoke_verdict(
    positive: Dict[str, Any],
    accepted: int,
    rejected: int,
) -> str:
    """Decide what the smoke test PROVED. Evaluated top-down, first match wins.

    The ordering is the whole design:

    1. ``accepts_noise`` outranks everything. An oracle that accepts random
       bytes out of a memory dump is a proven non-detector, and that stays the
       headline even when there is no ground truth to check against.
    2. No positive control is reported as its own verdict, never as a failure.
    3. ``discriminates`` requires BOTH halves: the key accepted AND at least
       one clean rejection. Without the second clause a dump that yielded zero
       usable negatives would green-light an oracle nothing had contradicted.
    4. Positive passed but nothing was rejected (no negatives, or every one
       raised) proves only half the claim -> ``inconclusive``.
    5. Otherwise the oracle failed to accept its own known-good key.
    """
    if accepted >= 1:
        return "accepts_noise"
    if not positive["present"]:
        return "no_positive_control"
    if positive["ok"] and rejected >= 1:
        return "discriminates"
    if positive["ok"]:
        return "inconclusive"
    return "never_accepts"


class OracleRegistry:
    """Per-process in-memory oracle catalog backed by a whitelisted dir."""

    def __init__(self, oracle_dir: Optional[Path], examples_dir: Path) -> None:
        self._oracle_dir = Path(oracle_dir).expanduser() if oracle_dir else None
        self._examples_dir = Path(examples_dir).expanduser()
        self._entries: Dict[str, OracleEntry] = {}
        self._lock = threading.RLock()
        # Prevent the detection probe from dropping stale .pyc files
        # into the oracle dir. Global but harmless here — memdiver is a
        # CLI/server with no hot-reload needs.
        sys.dont_write_bytecode = True
        if self._oracle_dir is not None:
            self._oracle_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._oracle_dir, 0o700)
            except OSError:
                pass
            self._rehydrate()

    # ------------------------------------------------------------------
    # configuration state
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._oracle_dir is not None

    def require_enabled(self) -> Path:
        if self._oracle_dir is None:
            # Name the one-click route FIRST. The env var still works, but it
            # requires a server restart, and pointing users at it was the whole
            # reason the upload dropzone looked broken out of the box.
            raise OracleDisabled(
                "oracle execution is disabled; enable it from the pipeline's "
                "Oracle stage or POST /api/oracles/enable. It can also be "
                "pinned before startup with MEMDIVER_ORACLE_DIR, which must "
                "name a trusted, non-shared, user-writable-only directory"
            )
        return self._oracle_dir

    def enable(self, oracle_dir: Path) -> Path:
        """Point this live registry at *oracle_dir*, creating it at ``0o700``.

        Exists so the oracle dir can be turned on at runtime (see
        ``POST /api/oracles/enable``) instead of only at startup from
        ``MEMDIVER_ORACLE_DIR``.

        Deliberately NOT implemented as :func:`init_oracle_registry`: that
        constructs a *new* :class:`OracleRegistry` and rebinds the module
        singleton, which would silently drop ``_entries`` — every oracle
        already uploaded in this process would vanish from the catalog while
        its file stayed on disk. Mutating in place keeps them.

        The ``0o700`` is the same guarantee the constructor makes: oracles are
        executed from this directory, and
        ``engine.oracle._assert_safe_path`` refuses to load anything whose
        parent dir is group/world-writable.
        """
        path = Path(oracle_dir).expanduser()
        with self._lock:
            path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
            self._oracle_dir = path
        # After the lock: rehydrate takes it again for each entry it restores.
        self._rehydrate()
        logger.info("oracle registry enabled at %s", path)
        return path

    # ------------------------------------------------------------------
    # examples
    # ------------------------------------------------------------------

    def list_examples(self) -> List[Dict[str, Any]]:
        """Enumerate bundled example oracles under ``docs/oracle/examples/``."""
        if not self._examples_dir.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for entry in sorted(self._examples_dir.glob("*.py")):
            if entry.name.startswith("_"):
                continue
            try:
                shape = _detect_shape(entry)
            except OracleLoadError as exc:
                logger.warning("example oracle %s failed to load: %s",
                               entry.name, exc)
                continue
            head_lines = _read_head(entry)
            summary = next(
                (ln.strip('"" \t#') for ln in head_lines if ln.strip()),
                "",
            )
            config_template, config_placeholders = _example_config_template(entry)
            out.append({
                "filename": entry.name,
                "path": str(entry),
                "sha256": _sha256_file(entry),
                "size": entry.stat().st_size,
                "shape": shape,
                "summary": summary,
                "head_lines": head_lines,
                "config_template": config_template,
                "config_placeholders": config_placeholders,
            })
        return out

    # ------------------------------------------------------------------
    # upload / arm / dry-run / delete
    # ------------------------------------------------------------------

    def upload(
        self,
        *,
        filename: str,
        content: bytes,
        description: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> OracleEntry:
        """Store an oracle file and register it; validation is LENIENT here.

        Upload is the first of three gates, and the only one that has not yet
        seen the user's configuration:

        * upload / load example — LENIENT (hang/crash only), config ``{}``
        * :meth:`arm`             — STRICT, with the real config
        * run (``engine.brute_force``) — STRICT, with the real config

        Being strict here made the bundled ``gocryptfs.py`` example
        un-uploadable: it is a Shape-2 oracle whose ``build_oracle(config)``
        does ``config["sample_ciphertext"]``, so replaying it with ``{}``
        raised ``KeyError`` and the upload 400'd with the file already
        unlinked — through the very endpoint the UI steers users to. A
        reproducible exception at this point means "not configured yet", which
        is the normal state of a freshly-uploaded oracle, not a reason to
        refuse the file.

        What is NOT relaxed: a hanging or resource-killed oracle is still
        rejected, still in a capped subprocess, still BEFORE ``_detect_shape``
        imports the module in-process.
        """
        oracle_dir = self.require_enabled()
        # Accept the user's original filename for display but store
        # under a uuid so a malicious basename cannot escape oracle_dir.
        oracle_id = uuid.uuid4().hex
        safe_filename = Path(filename).name or "oracle.py"
        on_disk = oracle_dir / f"{oracle_id}.py"
        on_disk.write_bytes(content)
        try:
            os.chmod(on_disk, 0o600)
        except OSError:
            pass
        if (on_disk.stat().st_mode & stat.S_IWOTH):  # pragma: no cover
            on_disk.unlink(missing_ok=True)
            raise OracleRegistryError("stored oracle is world-writable; aborting")
        _purge_pycache(on_disk)
        sha = _sha256_file(on_disk)
        # Probe the untrusted module in a resource-capped subprocess BEFORE
        # _detect_shape() imports it in-process. That ORDER is the load-bearing
        # part and does not change; only the verdict is lenient now (see this
        # method's docstring). Probed with ``{}`` and not with *config*: the
        # real config is first exercised at arm(), where the user has confirmed
        # intent.
        #
        # Spelled out longhand rather than as assert_oracle_not_hostile()
        # because the tolerated branch still carries a diagnostic worth
        # logging — "stored, but does not build with an empty config" is
        # precisely the state a Shape-2 oracle awaiting its form is in, and an
        # operator reading the log should be able to see that, not silence.
        # Note the fail-closed shape: only the explicitly benign
        # OracleBuildError is tolerated; any other load failure rejects.
        try:
            validate_oracle_sandboxed(on_disk, {})
        except OracleBuildError as exc:
            logger.info(
                "oracle %s stored but does not build with an empty config "
                "(expected for a Shape-2 oracle awaiting configuration): %s",
                safe_filename,
                exc,
            )
        except OracleLoadError as exc:
            on_disk.unlink(missing_ok=True)
            raise OracleRegistryError(f"oracle failed to load: {exc}") from exc
        try:
            shape = _detect_shape(on_disk)
        except OracleLoadError as exc:
            on_disk.unlink(missing_ok=True)
            raise OracleRegistryError(
                f"oracle failed to load: {exc}"
            ) from exc
        entry = OracleEntry(
            oracle_id=oracle_id,
            filename=safe_filename,
            path=on_disk,
            sha256=sha,
            size=on_disk.stat().st_size,
            shape=shape,
            head_lines=_read_head(on_disk),
            description=description,
            config=dict(config or {}),
        )
        with self._lock:
            self._entries[oracle_id] = entry
        self._persist(entry)
        return entry

    def find_example(self, filename: str) -> Dict[str, Any]:
        """Resolve *filename* to its entry in the ENUMERATED example catalog.

        Deliberately not ``self._examples_dir / filename``: joining would make
        ``../../etc/passwd`` (or any absolute path) a readable file the server
        then stores and executes, whereas matching against the enumeration
        makes the set of reachable files exactly the set the catalog already
        advertises. Traversal is therefore an :class:`OracleNotFound`, not a
        read — the same answer a simple typo gets, which is the point.
        """
        wanted = Path(filename).name
        match = next(
            (e for e in self.list_examples() if e["filename"] == wanted),
            None,
        )
        if match is None or wanted != filename:
            raise OracleNotFound(f"unknown example oracle: {filename!r}")
        return match

    def load_example(
        self,
        filename: str,
        *,
        config: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
    ) -> OracleEntry:
        """Copy a bundled example into the oracle dir and register it.

        Bundled is NOT trusted: the bytes go through :meth:`upload` unchanged,
        so the example gets the identical treatment a user upload does —
        ``0o600``, ``__pycache__`` purge, the capped sandbox probe before any
        in-process import, and shape detection.

        *filename* is resolved by :meth:`find_example`, so an unknown or
        traversing name never reaches the filesystem.
        """
        match = self.find_example(filename)
        wanted = match["filename"]
        source = Path(match["path"])
        try:
            content = source.read_bytes()
        except OSError as exc:  # pragma: no cover - enumerated a moment ago
            raise OracleRegistryError(
                f"example oracle {wanted} could not be read: {exc}"
            ) from exc
        return self.upload(
            filename=wanted,
            content=content,
            description=description if description is not None else match["summary"],
            config=config,
        )

    def get(self, oracle_id: str) -> OracleEntry:
        _assert_safe_id(oracle_id)
        with self._lock:
            entry = self._entries.get(oracle_id)
        if entry is None:
            raise OracleNotFound(f"unknown oracle: {oracle_id}")
        return entry

    def list_entries(self) -> List[OracleEntry]:
        with self._lock:
            return list(self._entries.values())

    def set_config(
        self, oracle_id: str, config: Optional[Dict[str, Any]]
    ) -> OracleEntry:
        """Replace an entry's config; returns the entry.

        Separate from :meth:`upload` because the UI's order of operations is
        "drop the file, *then* fill in the form": the file has to land before
        there is anything to configure. Stores a copy so a later mutation of
        the caller's dict cannot retroactively change what arm() validated.
        Deliberately does NOT re-validate — :meth:`arm` is the gate.
        """
        entry = self.get(oracle_id)
        with self._lock:
            entry.config = dict(config or {})
        self._persist(entry)
        return entry

    def arm(
        self,
        oracle_id: str,
        client_sha: str,
        *,
        config: Optional[Dict[str, Any]] = None,
    ) -> OracleEntry:
        """Confirm intent to run this oracle, with its real configuration.

        Three checks, in order: the file has not changed under us, the client
        is looking at the same file we are, and the oracle actually loads with
        the config it will be run with. The last one is the gate that upload
        deliberately no longer performs (see :meth:`upload`) — arming is
        already the user-intent confirmation, so it is the right place to spend
        a full strict sandbox replay, and it is where a config naming a
        filesystem path first gets used.

        Passing *config* replaces the stored one first, so the UI can fill in
        the form and arm in a single round trip. A load failure leaves the
        entry UNARMED and is reported as :class:`OracleConfigInvalid` carrying
        the sandbox's own diagnostic, so the user sees
        ``KeyError('sample_ciphertext')`` attributed to their configuration
        rather than a bare traceback or a 500.

        Pre-checked for unexpanded ``${VAR}`` placeholders before the sandbox
        runs, so a template submitted verbatim is named as such instead of
        surfacing as a bare "No such file or directory".
        """
        entry = self.get(oracle_id)
        _purge_pycache(entry.path)
        current_sha = _sha256_file(entry.path)
        if current_sha != entry.sha256:
            raise OracleShaMismatch(
                f"stored sha256 no longer matches on-disk file "
                f"({entry.sha256[:12]}… vs {current_sha[:12]}…); re-upload"
            )
        if client_sha != entry.sha256:
            raise OracleShaMismatch(
                f"client sha256 mismatch ({client_sha[:12]}… vs "
                f"{entry.sha256[:12]}…); display is stale"
            )
        if config is not None:
            self.set_config(oracle_id, config)
        # AFTER set_config, so it judges the config this arm will actually
        # replay — a stored placeholder left over from a previous
        # load_example() is just as broken as one passed in here. Before the
        # sandbox, because a placeholder needs no subprocess to diagnose and
        # the sandbox's own verdict for it is the useless
        # FileNotFoundError this check exists to replace.
        _reject_unexpanded_placeholders(entry.config, filename=entry.filename)
        # STRICT, with the real config: unlike upload's lenient probe, a
        # reproducible exception here is fatal, because there is nothing left
        # downstream to fix it — the next thing that touches this oracle is the
        # run. Still a capped subprocess, still never calls verify().
        try:
            validate_oracle_sandboxed(entry.path, entry.config)
        except OracleLoadError as exc:
            # Name the keys we handed over. The sandbox reports the child's
            # exception via repr(), and repr(OSError) drops the filename — so
            # an unreadable sample_ciphertext arrives as a bare
            # "No such file or directory" with nothing to act on unless the
            # field names come from this side. Keys only, not values: enough
            # for the UI to highlight the offending field, without echoing a
            # user's filesystem layout into every log line. Phrased as
            # "config keys: …" by _describe_config_keys, because the bare list
            # read as "this key is the problem" when it only lists what was
            # sent.
            supplied = _describe_config_keys(entry.config)
            raise OracleConfigInvalid(
                f"oracle {entry.filename} could not be loaded with the supplied "
                f"configuration ({supplied}): {exc}. Check the oracle's config "
                f"values (a missing key is reported as a KeyError naming that "
                f"key)."
            ) from exc
        entry.armed = True
        entry.armed_at = time.time()
        self._persist(entry)
        return entry

    def delete(self, oracle_id: str) -> None:
        entry = self.get(oracle_id)
        with self._lock:
            self._entries.pop(oracle_id, None)
        try:
            entry.path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
        try:
            _sidecar_path(entry.path).unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
        _purge_pycache(entry.path)

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------

    def _persist(self, entry: OracleEntry) -> None:
        """Write ``entry``'s sidecar. Best-effort: logs, never raises.

        Losing persistence must not fail the upload/arm the user just made --
        the entry is already live in ``_entries`` and works for this process.

        ``0o600`` matches the ``.py``: the sidecar carries ``config``, which
        may name absolute filesystem paths or, for a third-party oracle, a
        passphrase. The mode is applied to the tmp file *before* the atomic
        replace, so the final path never exists world-readable.
        """
        try:
            atomic_write_text(
                _sidecar_path(entry.path),
                json.dumps(_entry_to_sidecar(entry), indent=2),
                mode=0o600,
            )
        except OSError as exc:  # pragma: no cover - disk-level failure
            logger.warning(
                "could not persist oracle %s metadata: %s", entry.filename, exc
            )

    def _rehydrate(self) -> None:
        """Restore entries from sidecars so a restart does not 404 them.

        Without this the registry is memory-only: a restart drops every
        config and arm state, orphans the ``.py`` files, and makes the
        pipeline's stored ``oracleId`` 404 mid-run -- with the wizard's Next
        button silently going dead because its entry vanished.

        Three refusals, each deliberate:

        * A sidecar whose sibling ``.py`` is missing is skipped (dangling).
        * The ``.py`` is **re-hashed** and compared to the stored digest. The
          whole point of the stored sha is to give :meth:`arm`'s
          display-vs-disk check something truthful to compare against;
          adopting an entry whose bytes changed while the server was down
          would hand a tampered file an id the UI already trusts.
        * ``armed`` is always restored as ``False``. Arming is not cached
          state, it is an authorization act: it is bound to a sha the user saw
          in the UI and echoed back, it is the one place the real config is
          replayed through the strict sandbox, and it is the gate between "a
          .py sits in a directory" and "this process will exec it". A restart
          invalidates all three. Restoring the *entry* is what fixes the 404;
          re-arming costs one click.
        """
        oracle_dir = self._oracle_dir
        if oracle_dir is None or not oracle_dir.is_dir():
            return
        restored = 0
        for sidecar in sorted(oracle_dir.glob("*.json")):
            entry = self._entry_from_sidecar(sidecar)
            if entry is None:
                continue
            with self._lock:
                self._entries[entry.oracle_id] = entry
            restored += 1
        if restored:
            logger.info("restored %d oracle(s) from %s", restored, oracle_dir)
        orphans = self.orphan_files()
        if orphans:
            logger.info(
                "%d oracle file(s) in %s have no metadata and were left alone: %s",
                len(orphans),
                oracle_dir,
                ", ".join(orphans),
            )

    def _entry_from_sidecar(self, sidecar: Path) -> Optional[OracleEntry]:
        """Parse one sidecar into an entry, or ``None`` with a logged reason."""
        try:
            payload = json.loads(sidecar.read_text())
        except (OSError, ValueError) as exc:
            logger.warning("ignoring unreadable oracle metadata %s: %s", sidecar.name, exc)
            return None
        if not isinstance(payload, dict) or payload.get("schema") != _SIDECAR_SCHEMA:
            logger.warning("ignoring oracle metadata %s: unsupported schema", sidecar.name)
            return None
        oracle_id = str(payload.get("oracle_id", ""))
        try:
            _assert_safe_id(oracle_id)
        except OracleRegistryError:
            logger.warning("ignoring oracle metadata %s: bad id", sidecar.name)
            return None
        py_path = sidecar.with_suffix(".py")
        if not py_path.is_file():
            logger.warning(
                "ignoring oracle metadata %s: %s is gone", sidecar.name, py_path.name
            )
            return None
        _purge_pycache(py_path)
        try:
            on_disk_sha = _sha256_file(py_path)
        except OSError as exc:  # pragma: no cover
            logger.warning("ignoring oracle %s: %s", py_path.name, exc)
            return None
        if on_disk_sha != payload.get("sha256"):
            logger.warning(
                "refusing to restore oracle %s: file changed since it was stored "
                "(sha256 on disk does not match its metadata)",
                py_path.name,
            )
            return None
        armed_at = payload.get("armed_at")
        return OracleEntry(
            oracle_id=oracle_id,
            filename=str(payload.get("filename", py_path.name)),
            path=py_path,
            sha256=on_disk_sha,
            size=int(payload.get("size", py_path.stat().st_size)),
            shape=int(payload.get("shape", 1)),
            head_lines=_read_head(py_path),
            uploaded_at=float(payload.get("uploaded_at", time.time())),
            armed=False,
            description=payload.get("description"),
            config=dict(payload.get("config") or {}),
            armed_at=armed_at,
            previously_armed=armed_at is not None,
        )

    def orphan_files(self) -> List[str]:
        """``.py`` files in the oracle dir with no metadata and no live entry.

        Not deleted automatically: a boot-time process must never remove a
        user's file because a schema check failed. :meth:`prune_orphans` is
        the user-initiated counterpart.
        """
        oracle_dir = self._oracle_dir
        if oracle_dir is None or not oracle_dir.is_dir():
            return []
        with self._lock:
            live = {entry.path.name for entry in self._entries.values()}
        return sorted(
            py.name
            for py in oracle_dir.glob("*.py")
            if py.name not in live and not _sidecar_path(py).is_file()
        )

    def prune_orphans(self) -> List[str]:
        """Delete the files :meth:`orphan_files` reports; returns their names."""
        oracle_dir = self.require_enabled()
        removed: List[str] = []
        for name in self.orphan_files():
            path = oracle_dir / name
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:  # pragma: no cover
                logger.warning("could not remove orphaned oracle %s: %s", name, exc)
                continue
            _purge_pycache(path)
            removed.append(name)
        if removed:
            logger.info("removed %d orphaned oracle file(s)", len(removed))
        return removed

    def require_armed(self, oracle_id: str) -> OracleEntry:
        entry = self.get(oracle_id)
        if not entry.armed:
            raise OracleNotArmed(f"oracle {oracle_id} not armed")
        return entry

    def _load_verify(self, entry: OracleEntry) -> Callable[[bytes], bool]:
        """Build ``entry``'s oracle, translating any user-code failure.

        The loading half of :meth:`dry_run`, shared with
        :meth:`smoke_test` so both report a misconfigured oracle with the
        same sentence instead of one of them 500-ing.
        """
        _purge_pycache(entry.path)
        # Before load_oracle, for the same reason arm() checks before its
        # sandbox: dereferencing a placeholder produces a true-but-useless
        # FileNotFoundError, and dry_run is the surface users reach FIRST.
        _reject_unexpanded_placeholders(entry.config, filename=entry.filename)
        # The entry's own config, not {}: a Shape-2 oracle with a required key
        # cannot be built without it, so hardcoding {} made the smoke test
        # explode for exactly the oracles it is most useful on.
        #
        # Translated to a registry error because a smoke test run before the
        # oracle has been configured is an ordinary user mistake, and anything
        # raised here reaches the router unmapped — i.e. a 500 for what is
        # really "fill in the form first". Broad on purpose: load_oracle wraps
        # the *import* in OracleLoadError but calls ``build_oracle(config)``
        # unwrapped, so the user oracle's own KeyError/ValueError arrives
        # bare. repr() keeps the exception type visible, matching what the
        # sandbox reports for the same failure at arm().
        try:
            verify = load_oracle(entry.path, config=entry.config)
        except Exception as exc:  # noqa: BLE001 - any user-code load failure
            supplied = _describe_config_keys(entry.config)
            raise OracleConfigInvalid(
                f"oracle {entry.filename} could not be loaded with the supplied "
                f"configuration ({supplied}): {exc!r}"
            ) from exc
        return verify

    def dry_run(
        self,
        oracle_id: str,
        *,
        samples: List[bytes],
    ) -> Dict[str, Any]:
        """Run the oracle against ``samples`` and report pass/fail counts.

        Does NOT require the oracle to be armed: the whole point is to
        let a user smoke-test before committing to arming + running.

        Pre-checked for unexpanded ``${VAR}`` placeholders, so smoke-testing a
        bundled template straight off the Examples tab says which key still
        holds a placeholder instead of failing on an unopenable path.
        """
        entry = self.get(oracle_id)
        verify = self._load_verify(entry)
        return {"oracle_id": oracle_id, **_grade_samples(verify, samples)}

    def _requires_cipher_for(self, entry: OracleEntry) -> Optional[str]:
        """The cipher this oracle declares it needs, if it is a known example.

        Best-effort: an uploaded third-party oracle has no bundled ``.toml``
        and simply gets ``None``. Used only to add a caveat, never to block.
        """
        try:
            example = self.find_example(entry.filename)
            automation = load_example_automation(Path(example["path"]).with_suffix(".toml"))
            return automation.requires_cipher
        except Exception:  # noqa: BLE001 - a missing/unreadable template is not an error
            return None

    def smoke_test(
        self,
        oracle_id: str,
        *,
        source_paths: Sequence[str],
        key_size: int = 32,
        negatives: int = 15,
        include_positive_control: bool = True,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Grade the oracle against a positive control plus real dump bytes.

        This exists because :meth:`dry_run` grades whatever the *client* sends,
        and the web UI sent 16 hard-coded synthetic byte strings -- so a
        correct oracle and one whose ``verify`` is wired to ``return False``
        both scored zero passes. A smoke test that cannot tell those apart is
        not a smoke test.

        Here the samples are composed server-side: one candidate the oracle
        MUST accept (the run's recorded master key) and N it must reject (bytes
        read at random offsets from the dump itself). The verdict is about
        *discrimination*, not about a raw pass count.

        Like :meth:`dry_run`, does NOT require the oracle to be armed -- the
        whole point is triage before committing to arming.

        The response never contains sample bytes. The positive control IS the
        run's master key; echoing it back would hand it to any HTTP client.
        """
        entry = self.get(oracle_id)
        if not source_paths:
            raise OracleRegistryError(
                "a smoke test needs at least one dump to sample from; "
                "pick your dumps before testing the oracle"
            )
        # Before any dump I/O, so a misconfigured oracle is reported as such
        # rather than after a multi-second read of a multi-GB dump.
        verify = self._load_verify(entry)
        composed = compose_smoke_samples(
            source_paths,
            key_size=key_size,
            negatives=negatives,
            include_positive_control=include_positive_control,
            requires_cipher=self._requires_cipher_for(entry),
            seed=seed,
        )
        positive = composed.positive
        samples: List[bytes] = []
        if positive is not None:
            samples.append(positive.sample)
        samples.extend(composed.negatives)
        graded = _grade_samples(verify, samples)
        results = graded["results"]

        if positive is not None:
            head = results[0]
            positive_payload: Dict[str, Any] = {
                "present": True,
                "index": 0,
                "ok": bool(head["ok"]) if "error" not in head else False,
                "error": head.get("error"),
                "source": positive.source,
                "provenance_label": positive.provenance_label,
                "reason": None,
            }
            negative_results = results[1:]
        else:
            # ok stays None, NOT False: "there was no ground truth to test
            # with" is not "the oracle rejected the key", and rendering the
            # absence as a failure is exactly the confusion this endpoint
            # exists to remove.
            positive_payload = {
                "present": False,
                "index": None,
                "ok": None,
                "error": None,
                "source": None,
                "provenance_label": None,
                "reason": composed.no_positive_reason,
            }
            negative_results = results

        accepted = sum(1 for r in negative_results if r.get("ok") and "error" not in r)
        neg_errors = sum(1 for r in negative_results if "error" in r)
        rejected = len(negative_results) - accepted - neg_errors

        return {
            "oracle_id": oracle_id,
            **graded,
            "positive": positive_payload,
            "negatives": {
                "count": len(negative_results),
                "accepted": accepted,
                "rejected": rejected,
                "errors": neg_errors,
                "key_size": composed.key_size,
                "low_entropy_included": composed.low_entropy_included,
                "offsets": list(composed.negative_offsets),
            },
            "dump": (
                {
                    "path": composed.dump_path,
                    "format": composed.dump_format or "",
                    "view": composed.view,
                    "size": composed.dump_size,
                }
                if composed.dump_path
                else None
            ),
            "verdict": _smoke_verdict(positive_payload, accepted, rejected),
            "caveats": list(composed.caveats),
        }


# ----------------------------------------------------------------------
# singleton
# ----------------------------------------------------------------------

_default_registry: Optional[OracleRegistry] = None
_default_lock = threading.Lock()


def init_oracle_registry(
    *,
    oracle_dir: Optional[Path],
    examples_dir: Path,
) -> OracleRegistry:
    global _default_registry
    with _default_lock:
        _default_registry = OracleRegistry(
            oracle_dir=oracle_dir,
            examples_dir=examples_dir,
        )
    return _default_registry


def get_oracle_registry() -> OracleRegistry:
    if _default_registry is None:
        raise RuntimeError("OracleRegistry not initialized")
    return _default_registry


def reset_oracle_registry() -> None:
    global _default_registry
    with _default_lock:
        _default_registry = None
