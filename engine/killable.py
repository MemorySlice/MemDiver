"""Run one function in a CHILD PROCESS the caller can kill mid-flight.

Why: a job runs in a pool worker and cancels by *polling* an event. Python cannot
stop a running thread, so a stage that never polls (a pakunoda probe, vol3
stacking) would hold the cancel hostage until it finished. A child process can
be terminated, so the stage runs there and the parent polls.

Wire format (child -> parent, one-way ``Pipe``), tagged tuples:
``("progress", dict)``, ``("ok", result)``, ``("error", {...})``. A child that
dies without sending anything is reported as ``worker_crashed`` - never as a
silent empty result.
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import multiprocessing
import threading
import traceback
from typing import Any, Callable, Dict, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory

__all__ = ["run_killable"]

_TRACEBACK_TAIL_LINES = 12
_LOG = logging.getLogger(__name__)


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return {"repr": repr(value)[:500]}


def _error_message(exc: BaseException) -> Dict[str, Any]:
    """The ``("error", ...)`` body for an exception raised by the target."""
    if isinstance(exc, CapabilityError):
        return {"kind": "capability", "message": exc.message, "category": exc.category.name,
                "status": exc.status, "code": exc.code, "details": _json_safe(exc.details)}
    tail = traceback.format_exc().strip().splitlines()[-_TRACEBACK_TAIL_LINES:]
    return {"kind": "exception", "message": f"{type(exc).__name__}: {exc}",
            "details": {"exception_type": type(exc).__name__, "traceback_tail": tail}}


def _accepts_progress(fn: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return "progress" in params or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _child_main(target: str, kwargs: Dict[str, Any], conn: Any) -> None:
    """Spawned entry: arm the parent-death watchdog, run ``target``, report once."""
    from memdiver.core.process_guard import guard_child_process
    guard_child_process()
    lock = threading.Lock()

    def send(message: Any) -> None:
        with lock:
            conn.send(message)

    try:
        module_name, _, function_name = target.partition(":")
        fn = getattr(importlib.import_module(module_name), function_name)
        call_kwargs = dict(kwargs)
        if _accepts_progress(fn):
            call_kwargs["progress"] = lambda info: send(("progress", dict(info)))
        result = fn(**call_kwargs)
        send(("ok", result))
    except BaseException as exc:  # noqa: BLE001 - everything must cross as a message
        try:
            send(("error", _error_message(exc)))
        except Exception:  # noqa: BLE001 - parent already gone / unpicklable: exit code tells
            raise SystemExit(70)
    finally:
        conn.close()


def _failure(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INTERNAL, code=code, details=details)


def _raise_error(body: Dict[str, Any]) -> None:
    if body.get("kind") == "capability":
        raise CapabilityError(
            body["message"], category=ErrorCategory[body["category"]], status=body.get("status"),
            code=body.get("code"), details=body.get("details"))
    raise _failure("worker_failed", body["message"], body.get("details"))


def _cancelled(cancel: Callable[[], bool]) -> bool:
    try:
        return bool(cancel())
    except Exception:  # noqa: BLE001 - a broken cancel callable means "not cancelled"
        return False


def _report(on_progress: Callable[[dict], None], body: dict) -> None:
    """Forward one progress message; a failing reporter never aborts the work it reports on."""
    try:
        on_progress(body)
    except Exception:  # noqa: BLE001 - progress is advisory
        _LOG.debug("progress callback failed", exc_info=True)


def _reap(proc: Any, grace_s: float, *, kill: bool) -> None:
    """Make sure the child is gone and joined.

    ``kill`` False: the child already reported, so give it ``grace_s`` to exit on
    its own. Either way a survivor is terminated, then killed after ``grace_s``.
    """
    if not kill:
        proc.join(grace_s)
    if proc.is_alive():
        proc.terminate()
        proc.join(grace_s)
        if proc.is_alive():
            proc.kill()
    proc.join()


def _receive(conn: Any, proc: Any, poll_s: float, cancel: Callable[[], bool],
             on_progress: Optional[Callable[[dict], None]]) -> Any:
    """The parent loop: forward progress, watch ``cancel``, return the ok result."""
    while True:
        if conn.poll(poll_s):
            try:
                tag, body = conn.recv()
            except EOFError:
                proc.join()
                raise _failure("worker_crashed",
                               f"worker process exited without a result (exit code "
                               f"{proc.exitcode})", {"exit_code": proc.exitcode}) from None
            except Exception as exc:  # noqa: BLE001 - unpicklable / corrupt message
                raise _failure("worker_failed",
                               f"worker result could not be received: "
                               f"{type(exc).__name__}: {exc}") from exc
            if tag == "ok":
                return body
            if tag == "error":
                _raise_error(body)
            if tag == "progress" and on_progress is not None:
                _report(on_progress, body)
        if _cancelled(cancel):
            raise CapabilityError("cancelled", category=ErrorCategory.PRECONDITION,
                                  code="cancelled")


def run_killable(target: str, kwargs: Dict[str, Any], *, cancel: Callable[[], bool],
                 on_progress: Optional[Callable[[dict], None]] = None,
                 poll_s: float = 0.1, grace_s: float = 2.0) -> Any:
    """Run ``target`` (``"module:function"``) with ``kwargs`` in a spawned child.

    ``progress(dict)`` is passed to the target as kwarg ``progress`` only when it
    accepts one, and forwarded to ``on_progress``. ``cancel()`` is polled every
    ``poll_s``; a cancel terminates the child (kill after ``grace_s``) and raises
    ``CapabilityError(code="cancelled")``. The child is always reaped.
    Raises ``CapabilityError`` ``worker_failed`` / ``worker_crashed`` otherwise.
    """
    ctx = multiprocessing.get_context("spawn")
    reader, writer = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child_main, args=(target, dict(kwargs), writer))
    proc.start()
    writer.close()  # the parent holds only the read end, so a dead child yields EOF
    ok = False
    try:
        result = _receive(reader, proc, poll_s, cancel, on_progress)
        ok = True
        return result
    finally:
        reader.close()
        _reap(proc, grace_s, kill=not ok)
