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
import logging
import os
import shutil
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.engine.oracle import (
    OracleBuildError,
    OracleLoadError,
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
            "description": self.description,
            "config": dict(self.config),
        }


def _purge_pycache(path: Path) -> None:
    """Delete the ``__pycache__/`` directory next to ``path``.

    Importing from a fresh .py file can still pick up a stale .pyc the
    attacker dropped alongside it; purging proactively avoids that
    hole. Missing or empty dirs are fine.
    """
    cache_dir = path.parent / "__pycache__"
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir, ignore_errors=True)


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


def _example_config_template(path: Path) -> Optional[Dict[str, Any]]:
    """Parse the sibling ``<stem>.toml`` of a bundled example, if it ships one.

    A Shape-2 example is useless without its parameters, and the bundled
    ``.toml`` is the authoritative statement of which keys it wants — so it is
    surfaced as a *template* the UI can render as a prefilled form instead of
    making the user read the example's docstring.

    Values are passed through verbatim. ``gocryptfs.toml`` deliberately ships a
    literal ``${MEMDIVER_FIXTURE_ROOT}`` placeholder; expanding it here would
    silently hand the user a path that exists on nobody's machine, whereas an
    unexpanded placeholder reads as "fill this in", which is what it is.
    Parsed with :func:`engine.oracle.load_oracle_config`, the same loader the
    CLI's ``--oracle-config`` uses, so the two can never disagree on syntax.
    """
    toml_path = path.with_suffix(".toml")
    if not toml_path.is_file():
        return None
    try:
        return load_oracle_config(toml_path)
    except (OracleLoadError, ValueError) as exc:
        # A malformed bundled template must not blank the whole Examples tab.
        logger.warning("example config %s failed to parse: %s", toml_path.name, exc)
        return None


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
            out.append({
                "filename": entry.name,
                "path": str(entry),
                "sha256": _sha256_file(entry),
                "size": entry.stat().st_size,
                "shape": shape,
                "summary": summary,
                "head_lines": head_lines,
                "config_template": _example_config_template(entry),
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
        return entry

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

        *filename* is resolved against the ENUMERATED :meth:`list_examples`
        result rather than joined onto ``self._examples_dir``. Joining would
        make ``../../etc/passwd`` (or any absolute path) a readable file the
        server then stores and executes; matching against the enumeration
        makes the set of loadable files exactly the set the catalog already
        advertises.
        """
        wanted = Path(filename).name
        match = next(
            (e for e in self.list_examples() if e["filename"] == wanted),
            None,
        )
        if match is None or wanted != filename:
            raise OracleNotFound(f"unknown example oracle: {filename!r}")
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
            # user's filesystem layout into every log line.
            supplied = ", ".join(sorted(entry.config)) or "no values supplied"
            raise OracleConfigInvalid(
                f"oracle {entry.filename} could not be loaded with the supplied "
                f"configuration ({supplied}): {exc}. Check the oracle's config "
                f"values (a missing key is reported as a KeyError naming that "
                f"key)."
            ) from exc
        entry.armed = True
        return entry

    def delete(self, oracle_id: str) -> None:
        entry = self.get(oracle_id)
        with self._lock:
            self._entries.pop(oracle_id, None)
        try:
            entry.path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
        _purge_pycache(entry.path)

    def require_armed(self, oracle_id: str) -> OracleEntry:
        entry = self.get(oracle_id)
        if not entry.armed:
            raise OracleNotArmed(f"oracle {oracle_id} not armed")
        return entry

    def dry_run(
        self,
        oracle_id: str,
        *,
        samples: List[bytes],
    ) -> Dict[str, Any]:
        """Run the oracle against ``samples`` and report pass/fail counts.

        Does NOT require the oracle to be armed: the whole point is to
        let a user smoke-test before committing to arming + running.
        """
        entry = self.get(oracle_id)
        _purge_pycache(entry.path)
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
            supplied = ", ".join(sorted(entry.config)) or "no values supplied"
            raise OracleConfigInvalid(
                f"oracle {entry.filename} could not be loaded with the supplied "
                f"configuration ({supplied}): {exc!r}"
            ) from exc
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
            "oracle_id": oracle_id,
            "samples": len(samples),
            "passes": passes,
            "fails": fails,
            "errors": errors,
            "per_call_us_avg": round(t_total / max(1, len(samples) - errors), 2),
            "results": results,
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
