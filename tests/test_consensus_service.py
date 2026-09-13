"""Tests for engine.consensus_service — the shared open+build core.

These assert behavior-parity with the old copy-pasted skeleton
(``ExitStack`` → ``open_dump`` → ``ConsensusVector.build_from_sources``) that
the CLI / API / MCP consensus sites used to each carry.
"""
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.dump_source import open_dump
from memdiver.engine.consensus import ConsensusVector
from memdiver.engine.consensus_service import (
    build_consensus,
    open_consensus_sources,
)


def _make_dumps(data_list):
    """Create temporary raw dump files from byte data."""
    paths = []
    for data in data_list:
        f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
        f.write(data)
        f.close()
        paths.append(Path(f.name))
    return paths


def _build_old_way(paths, normalize):
    """The exact skeleton the three call sites used to copy-paste."""
    with ExitStack() as stack:
        sources = [stack.enter_context(open_dump(Path(p))) for p in paths]
        cm = ConsensusVector()
        cm.build_from_sources(sources, normalize=normalize)
    return cm


def _sample_dumps():
    return _make_dumps([
        b"\x00" * 50 + b"\xFF" * 50,
        b"\x00" * 50 + b"\x00" * 50,
        b"\x00" * 50 + b"\x80" * 50,
    ])


def test_build_consensus_matches_old_skeleton():
    """build_consensus must produce a byte-identical vector to the old code."""
    for normalize in (False, True):
        paths = _sample_dumps()
        old = _build_old_way(paths, normalize)
        new = build_consensus(paths, normalize=normalize)
        assert np.array_equal(np.asarray(old.variance), np.asarray(new.variance))
        assert old.reference_bytes == new.reference_bytes
        assert old.classification_counts() == new.classification_counts()
        assert old.size == new.size
        assert old.num_dumps == new.num_dumps


def test_build_consensus_returns_consensus_vector():
    """The return value exposes every attribute/method the call sites read."""
    cm = build_consensus(_sample_dumps())
    assert isinstance(cm, ConsensusVector)
    assert cm.size == 100
    assert cm.num_dumps == 3
    # attributes/methods read by the API, MCP, and CLI sites
    _ = cm.variance
    _ = cm.reference_bytes
    _ = cm.classification_counts()
    _ = cm.get_static_regions()
    _ = cm.get_volatile_regions()


def test_on_source_hook_called_per_source_in_order_before_build():
    """on_source runs once per opened source, in order, before the build."""
    paths = _sample_dumps()
    seen = []
    cm = build_consensus(paths, on_source=lambda s: seen.append(s))
    assert len(seen) == len(paths)
    # every element is a distinct opened source object
    assert len({id(s) for s in seen}) == len(paths)
    assert cm.size == 100


def test_open_consensus_sources_yields_open_sources_and_closes_them():
    """The context manager yields opened sources and closes them on exit."""
    paths = _sample_dumps()
    with open_consensus_sources(paths) as sources:
        assert len(sources) == len(paths)
        # opened sources are readable (an unopened MslDumpSource would raise)
        for src in sources:
            assert len(src.read_all()) == 100


def test_build_consensus_forwards_key_material():
    """key_material is forwarded to open_dump; empty/None opens unencrypted."""
    paths = _sample_dumps()
    cm_none = build_consensus(paths, key_material=None)
    cm_empty = build_consensus(paths, key_material={})
    assert cm_none.size == cm_empty.size == 100
    assert cm_none.classification_counts() == cm_empty.classification_counts()


# ---------------------------------------------------------------------------
# Missing-file failures must be typed, not bare.
#
# ``core.dump_io.DumpReader.open`` raises the builtin FileNotFoundError, which
# is NOT a CapabilityError, so it bypassed the API's global error funnel and
# surfaced as a 500 with a full ASGI traceback instead of a 404. The skeleton
# translates it, so every surface (HTTP, CLI, MCP) reports it the same way.
# ---------------------------------------------------------------------------


def test_open_consensus_sources_missing_path_raises_service_error(tmp_path):
    import pytest

    from memdiver.core.service_errors import (
        ErrorCategory,
        FileNotFoundServiceError,
    )

    missing = tmp_path / "gone.msl"
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        with open_consensus_sources([str(missing)]):
            pass
    assert excinfo.value.category is ErrorCategory.NOT_FOUND
    assert excinfo.value.status == 404
    assert "gone.msl" in excinfo.value.message


def test_build_consensus_missing_path_raises_service_error(tmp_path):
    import pytest

    from memdiver.core.service_errors import FileNotFoundServiceError

    good = _make_dumps([b"\xAA" * 4096])[0]
    missing = str(tmp_path / "gone.msl")
    with pytest.raises(FileNotFoundServiceError):
        build_consensus([good, missing])


def test_partially_opened_sources_are_closed_when_one_path_is_missing(tmp_path):
    """The ExitStack must still unwind: the first dump opened fine."""
    import pytest

    from memdiver.core.service_errors import FileNotFoundServiceError

    good = _make_dumps([b"\xAA" * 4096])[0]
    opened = []

    import memdiver.engine.consensus_service as svc

    real_open = svc.open_dump

    def _tracking_open(path, **kw):
        src = real_open(path, **kw)
        opened.append(src)
        return src

    svc.open_dump = _tracking_open
    try:
        with pytest.raises(FileNotFoundServiceError):
            with open_consensus_sources([good, str(tmp_path / "gone.msl")]):
                pass
    finally:
        svc.open_dump = real_open

    # The good source was entered, and the stack closed it on the way out.
    assert opened, "the first path should have been opened"
