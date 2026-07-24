"""Unit tests for the CLI inspect presenter (``cli.present_inspect_cli``).

These pin the pure ``ServiceResult -> (machine_payload, exit_code, stderr_msg)``
mapping the CLI inspect handlers rely on, independently of any dump/reader:

* A locked (undecrypted) result reproduces exactly the legacy error dict the
  tool layer used to return under the ``report_key_status`` default
  (``{"error": <hint>, "tag_status": …}``), exit code ``1``, stderr = the hint.
* A decrypted result (valid / not-encrypted / empty payload) passes its payload
  through untouched with exit code ``0`` and no stderr message.
* ``_present_inspect_cli_call`` turns a producer's raised ``CapabilityError``
  (e.g. ``FileNotFoundServiceError``) back into the SAME error tuple the legacy
  ``{"error": …}`` dict path produced.

Also covers ``cli.to_cli_exit`` — the Phase 3 backstop that maps a
propagating ``CapabilityError`` to a CLI stderr line + process exit code
(``main()``'s ``except CapabilityError`` clause).
"""

import io
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.cli import (
    _KEY_FLAGS_HINT,
    _present_inspect_cli_call,
    present_inspect_cli,
    to_cli_exit,
)
from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
)
from memdiver.core.service_result import (
    KeyStatus,
    Resolution,
    ServiceResult,
    StatusBlock,
)
from memdiver.msl.enums import TagStatus


class _Stub:
    """Minimal stand-in exposing a ``tag_status`` for ``KeyStatus.from_source``."""

    def __init__(self, tag_status):
        self.tag_status = tag_status


def _locked_result(tag_status):
    key = KeyStatus.from_source(_Stub(tag_status))
    return ServiceResult(
        payload={"regions": []},
        status=StatusBlock(resolution=Resolution.UNRESOLVED, key=key),
    )


def _ok_result(payload, tag_status=TagStatus.VALID):
    key = KeyStatus(tag_status=tag_status, decrypted=True)
    return ServiceResult(
        payload=payload,
        status=StatusBlock(resolution=Resolution.OK, key=key),
    )


def test_present_missing_key_locked():
    result = _locked_result(TagStatus.MISSING_KEY)
    # The CLI augments the neutral core hint with its own flag guidance.
    expected = f"{result.status.key.hint}; {_KEY_FLAGS_HINT}"

    payload, exit_code, stderr_msg = present_inspect_cli(result)

    assert payload == {"error": expected, "tag_status": "missing_key"}
    assert exit_code == 1
    assert stderr_msg == expected
    assert "encrypted" in stderr_msg
    assert "--key-file" in stderr_msg  # CLI flag guidance sourced from cli.py


def test_present_corrupted_locked():
    result = _locked_result(TagStatus.CORRUPTED)
    expected = f"{result.status.key.hint}; {_KEY_FLAGS_HINT}"

    payload, exit_code, stderr_msg = present_inspect_cli(result)

    assert payload == {"error": expected, "tag_status": "corrupted"}
    assert exit_code == 1
    assert stderr_msg == expected


def test_present_valid_ok_passes_payload_through():
    body = {"processes": [{"pid": 7}]}
    result = _ok_result(body, tag_status=TagStatus.VALID)

    payload, exit_code, stderr_msg = present_inspect_cli(result)

    assert payload is body
    assert exit_code == 0
    assert stderr_msg is None


def test_present_not_encrypted_ok():
    body = {"modules": []}
    result = _ok_result(body, tag_status=TagStatus.NOT_ENCRYPTED)

    payload, exit_code, stderr_msg = present_inspect_cli(result)

    assert payload == {"modules": []}
    assert exit_code == 0
    assert stderr_msg is None


def test_present_empty_payload_ok():
    result = ServiceResult(payload={}, status=StatusBlock())

    payload, exit_code, stderr_msg = present_inspect_cli(result)

    assert payload == {}
    assert exit_code == 0
    assert stderr_msg is None


def test_call_reproduces_legacy_file_not_found_tuple():
    def produce():
        raise FileNotFoundServiceError("File not found: /nope.msl")

    payload, exit_code, stderr_msg = _present_inspect_cli_call(produce)

    assert payload == {"error": "File not found: /nope.msl"}
    assert exit_code == 1
    assert stderr_msg == "File not found: /nope.msl"


def test_call_merges_error_details():
    def produce():
        raise OffsetOutOfRangeError(
            "offset out of range",
            details={"offset": 99, "file_size": 10, "view": "raw", "format": "msl"},
        )

    payload, exit_code, stderr_msg = _present_inspect_cli_call(produce)

    assert payload == {
        "error": "offset out of range",
        "offset": 99,
        "file_size": 10,
        "view": "raw",
        "format": "msl",
    }
    assert exit_code == 1
    assert stderr_msg == "offset out of range"


def test_call_passes_through_ok_producer():
    def produce():
        return ServiceResult.ok({"handles": []})

    payload, exit_code, stderr_msg = _present_inspect_cli_call(produce)

    assert payload == {"handles": []}
    assert exit_code == 0
    assert stderr_msg is None


# ---------------------------------------------------------------------------
# to_cli_exit — Phase 3 backstop: category -> exit code + stderr message.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category, expected_exit_code",
    [
        (ErrorCategory.NOT_FOUND, 3),
        (ErrorCategory.INVALID_INPUT, 2),
        (ErrorCategory.PRECONDITION, 2),
        (ErrorCategory.UNSUPPORTED, 2),
        (ErrorCategory.INTERNAL, 1),
    ],
)
def test_to_cli_exit_maps_category_to_exit_code(category, expected_exit_code):
    err = CapabilityError("something went wrong", category=category)
    stream = io.StringIO()

    exit_code = to_cli_exit(err, stream=stream)

    assert exit_code == expected_exit_code
    assert stream.getvalue() == "memdiver: ERROR — something went wrong\n"


def test_to_cli_exit_logs_traceback_for_internal(caplog):
    err = CapabilityError("boom", category=ErrorCategory.INTERNAL)
    stream = io.StringIO()

    with caplog.at_level(logging.ERROR, logger="memdiver.cli"):
        to_cli_exit(err, stream=stream)

    assert any("internal error" in rec.message for rec in caplog.records)


def test_to_cli_exit_does_not_log_for_non_internal(caplog):
    err = CapabilityError("bad input", category=ErrorCategory.INVALID_INPUT)
    stream = io.StringIO()

    with caplog.at_level(logging.ERROR, logger="memdiver.cli"):
        to_cli_exit(err, stream=stream)

    assert caplog.records == []
