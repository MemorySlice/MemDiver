"""Proof harness for the emitted Volatility3 plugin: load it and RUN it.

Everything MemDiver knew about its emitted vol3 plugins before B5.0 came from
``ast.parse`` plus substring assertions over the ~7 KB generated file. That
proves the text is syntactically Python. It does not prove the plugin *imports*
against a real framework, that its requirement block validates, that its
scanner fires, or that the row it emits points at the key -- and in fact the
template as shipped before B5.1 could not even be imported into a fresh
interpreter (see
:func:`test_emitted_plugin_module_level_format_hints_is_a_bug`).

This file is the instrument for the fixes that follow. Two of its tests are
therefore deliberately *not* green-by-construction:

* the bug-(a) guard WAS ``xfail(strict=True)``. B5.1 fixed the template and
  removed the marker; that red->green transition (observed:
  ``AttributeError: ... has no attribute 'format_hints'`` -> clean load) is what
  proves the guard actually guards. Its control test,
  ``test_bug_a_guard_would_be_vacuous_without_the_delattr``, stays.
* ``test_emitted_plugin_is_NOT_selective_at_the_default_pad`` asserts the *bad*
  number, on purpose. See its docstring.

**What B5.2 could NOT prove here, stated plainly.** The ``--pid`` fix is covered
for its declared requirements, for surviving a dump with no kernel module, for
the loudness of its failure, and for the argument SHAPE it hands
``list_tasks``/``list_processes``. It is NOT covered end to end:
``proc.add_process_layer()`` and the process-layer scan that follows it need a
real kernel memory image plus a matching ISF, and neither this repository nor the
machine these tests were written on has one. PID *narrowing* therefore remains
unproven -- see ``CHANGELOG.md``. Nothing in the bug-(b) block below should be
read as end-to-end PID coverage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.detector_metrics import (
    _match_key_offset,
    _match_length,
    _match_start,
    score_intervals,
)
from memdiver.engine.truth_labels import TruthInterval
from memdiver.engine.vol3_emit import emit_plugin_for_hit
from memdiver.engine.vol3_verify import (
    HAS_VOLATILITY3,
    VOL3_MISSING,
    Vol3Hit,
    Vol3VerifyReport,
    # Private, deliberately: the bug-(c) tests below need a context this module's
    # public entry points do not build (they register ONE flat layer), and
    # re-implementing the TreeGrid walk in the test would let the two drift.
    _column_index,
    _rows,
    anchor_stats,
    framework_version,
    load_plugin_class,
    run_over_buffer,
    run_over_file,
    verify_key_recovered,
)
from tests._emit_pins import synth_hit
from tests.fixtures.tls_ground_truth import tls_dumps_dir

requires_vol3_import = pytest.mark.skipif(
    not HAS_VOLATILITY3,
    reason='volatility3 not importable; pip install "memdiver[vol]"',
)

# --------------------------------------------------------------------------- #
# The measured ground truth this file's selectivity numbers come from.
#
# One real dump, one real key, measured this session. The key sits inside an
# all-zero run of [370601, 371184) -- 71 bytes of zeros before it and 464 after
# -- which is what makes the default-pad anchor degenerate.
# --------------------------------------------------------------------------- #
_REAL_RUN = (
    "TLS12/100_iterations_Abort/openssl/openssl_run_12_1/"
    "20251025_104527_944938_pre_abort.dump"
)
REAL_KEY_OFFSET = 370_672
REAL_KEY_LENGTH = 48
REAL_DUMP_BYTES = 11_223_040
ZERO_RUN = (370_601, 371_184)


def real_dump() -> Path:
    """The one measured dump, or a skip naming it."""
    path = tls_dumps_dir() / _REAL_RUN
    if not path.is_file():
        pytest.skip(f"measured ground-truth dump not present: {path}")
    return path


def emit_for(
    reference: bytes,
    key_offset: int,
    key_length: int,
    pad: int,
    out_dir: Path,
    name: str,
) -> str:
    """Emit a plugin anchored on ``pad`` static bytes either side of the key.

    The variance profile is synthesised rather than measured because pad width,
    not variance, is the variable under test: static preamble, volatile key,
    static trailer is exactly the shape a real multi-dump consensus produces for
    a key, and it is what ``tests/_emit_pins.py::synth_hit`` builds too.
    """
    hit = {
        "offset": key_offset,
        "length": key_length,
        "neighborhood_start": key_offset - pad,
        "neighborhood_variance": [100.0] * pad + [15000.0] * key_length + [50.0] * pad,
    }
    path = emit_plugin_for_hit(hit, reference, name, out_dir / f"{name}.py")
    return path.read_text()


# --------------------------------------------------------------------------- #
# Contract: the dataclass field names detector_metrics duck-types on
# --------------------------------------------------------------------------- #

def test_vol3hit_exposes_the_attributes_detector_metrics_ducktypes():
    """``offset`` / ``length`` / ``key_offset`` are a cross-module CONTRACT.

    ``engine.detector_metrics`` deliberately does not import any scanner's match
    class; its ``_match_start`` / ``_match_length`` / ``_match_key_offset``
    helpers read those three attributes with ``getattr(match, name, None)``. A
    rename to something more descriptive (``pattern_offset``, say) would break
    nothing loudly: every containment pair would simply disappear and every
    metric would read 0.0 on a detector that works. This test is the tripwire.
    """
    hit = Vol3Hit(
        offset=1000, length=176, key_offset=64, key_length=48,
        key_hex="00" * 48, key_entropy=5.5, static_ratio=0.727,
    )
    # Read through detector_metrics' OWN accessors, not by attribute access --
    # those three functions are the contract, so exercising them is what makes
    # this a tripwire rather than a restatement of the dataclass.
    assert _match_start(hit) == 1000
    assert _match_length(hit) == 176
    assert _match_key_offset(hit) == 64
    assert hit.key_absolute_offset == 1064

    truth = TruthInterval(
        start=1064, length=48, secret_type="TEST",
        key_hex="00" * 48, client_random="ab" * 32, source="keylog",
    )
    scored = score_intervals([hit], [truth], tolerance_bytes=0)
    assert scored["containment"].precision == 1.0
    assert scored["containment"].recall == 1.0
    # Exact key-offset agreement too: 1000 + 64 == 1064.
    assert scored["exact"].recall == 1.0


def test_report_carries_match_count_as_a_field():
    """``match_count`` is a real field, not ``len(hits)``.

    ``hits`` is capped, so a selectivity claim has to be able to read the honest
    total even when the retained sample is smaller.
    """
    report = Vol3VerifyReport(
        framework_version=(2, 27, 0), plugin_class_name="X", layer_scanned="flat",
        layer_bytes=1024, match_count=5311, hits=(), expected_offset=None,
        expected_offset_reported=False, anchor_bytes=128,
        anchor_distinct_bytes=1, matches_per_mib=0.0,
    )
    assert report.match_count == 5311
    assert len(report.hits) == 0
    assert report.to_dict()["match_count"] == 5311


def test_missing_extra_message_uses_the_extra_install_hint():
    """The absence of ``volatility3`` is a class-1 error, not a broken install.

    ``core.install_hints`` splits "you forgot an extra" from "your base install
    is broken", and the whole point of probing softly here is to land in the
    first class. That requires ``"vol"`` in ``OPTIONAL_EXTRAS`` and NOT in
    ``NO_OP_EXTRAS``; if either changes this message silently degrades to the
    force-reinstall wording, which would send the user down a road that cannot
    end in a fix.
    """
    assert 'pip install "memdiver[vol]"' in VOL3_MISSING
    assert "force-reinstall" not in VOL3_MISSING


# --------------------------------------------------------------------------- #
# Anchor statistics -- pure text, no framework needed
# --------------------------------------------------------------------------- #

def test_anchor_stats_counts_static_bytes_and_distinct_values():
    source = 'YARA_RULE = """\n$key = { 00 00 00 ?? ?? AA 00 }\n"""'
    assert anchor_stats(source) == (5, 2)  # 00,00,00,AA,00 -> {0x00, 0xAA}


def test_anchor_stats_degrades_to_zero_on_an_unparseable_rule():
    """Anchor stats are diagnostics; a rule they cannot read must not raise."""
    assert anchor_stats("no rule here") == (0, 0)


def test_anchor_stats_on_a_real_emission(tmp_path):
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "AnchorStats")
    anchor_bytes, distinct = anchor_stats(source)
    assert anchor_bytes == 128, "64 bytes of preamble + 64 of trailer are static"
    # synth_hit's reference is random, so its anchor is information-rich --
    # the opposite of the real dump's all-zero neighborhood.
    assert distinct > 64, distinct


# --------------------------------------------------------------------------- #
# The bug-(a) guard
# --------------------------------------------------------------------------- #

@requires_vol3_import
def test_emitted_plugin_module_level_format_hints_is_a_bug(tmp_path, monkeypatch):
    """The emitted plugin must import with NOTHING having pre-bound format_hints.

    **FIXED in B5.1** -- this test was ``xfail(strict=True)`` and is now green;
    the marker had to come off, because with ``strict=True`` an XPASS is itself a
    failure. Observed transition: ``AttributeError: module
    'volatility3.framework.renderers' has no attribute 'format_hints'`` at the
    emitted module's ``_COLUMNS`` line before the fix, clean load after it. The
    template now does ``from volatility3.framework.renderers import
    format_hints`` explicitly, so the name resolves regardless of what else has
    been imported in the process.

    The template USED TO do ``from volatility3.framework import interfaces,
    renderers`` and then, at module level, build ``_COLUMNS`` out of
    ``renderers.format_hints.Hex``. ``renderers`` is a package; importing it
    does not bind its ``format_hints`` submodule, so a bare import raised
    ``AttributeError: module 'volatility3.framework.renderers' has no attribute
    'format_hints'``.

    It only ever worked by accident: 111 files under
    ``volatility3/framework/plugins/`` do ``from
    volatility3.framework.renderers import format_hints``, and any one of them
    executing binds the submodule on the parent for the rest of the process. So
    once Volatility3's own ``import_files`` plugin walk has run -- which is
    exactly what happens when a user runs ``vol`` -- the emitted plugin loads
    fine, and the bug is invisible.

    **The ``monkeypatch.delattr`` is what makes this test non-vacuous, and it
    must stay.** ``engine/vol3_verify.py`` itself imports ``format_hints`` (it
    needs it, and the import is documented there), and so does any earlier test
    in the session that touched the plugin walk. Without deleting the attribute
    first, this test would exec the plugin in a process where the name already
    resolves and would pass while the bug is still there -- which is precisely
    how the bug survived this long.
    """
    from volatility3.framework import renderers as vol3_renderers

    monkeypatch.delattr(vol3_renderers, "format_hints", raising=False)
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "BugAGuard")
    load_plugin_class(source, "memdiver_test_bug_a_guard")


@requires_vol3_import
def test_bug_a_guard_would_be_vacuous_without_the_delattr(tmp_path):
    """Prove the guard above measures something: WITHOUT the delattr it passes.

    This is the control. ``engine.vol3_verify`` binds ``format_hints`` on the
    parent package at import time, so with the attribute left in place the very
    same source loads without complaint. If this test ever fails, the guard
    above has stopped being a statement about ``format_hints`` and has started
    failing for some other reason.
    """
    from volatility3.framework import renderers as vol3_renderers

    assert hasattr(vol3_renderers, "format_hints"), (
        "engine.vol3_verify is supposed to have bound this at import time"
    )
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "BugAControl")
    plugin_cls = load_plugin_class(source, "memdiver_test_bug_a_control")
    assert plugin_cls.__name__ == "BugAControl"
    assert plugin_cls._required_framework_version == (2, 0, 0)


# --------------------------------------------------------------------------- #
# In-process execution against a synthetic buffer
# --------------------------------------------------------------------------- #

@requires_vol3_import
def test_framework_version_is_a_supported_major():
    major, minor, _patch = framework_version()
    assert major == 2, (
        "the emitted plugin declares _required_framework_version = (2, 0, 0); "
        f"framework major {major} would reject every plugin MemDiver emits"
    )
    assert minor >= 27, f"the `vol` extra floors at 2.27, got 2.{minor}"


@requires_vol3_import
def test_run_over_buffer_finds_the_key_in_its_own_reference(tmp_path):
    """The plugin, executed for real, reports the key it was emitted from.

    Constructing the plugin runs Volatility3's own ``unsatisfied()`` requirement
    gate and ``require_interface_version``; ``run()`` drives the real
    ``RegExScanner`` over a real layer; the row comes back through a real
    ``TreeGrid``. None of that was exercised by any test before B5.0.
    """
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "BufferRun")
    report = run_over_buffer(source, ref, expected_offset=256)

    assert report.match_count == 1, report.to_dict()
    assert report.expected_offset_reported is True
    assert report.layer_bytes == len(ref)
    assert report.layer_scanned == "flat"
    assert report.framework_version[0] == 2
    hit = report.hits[0]
    assert hit.offset == 192, "window starts one 64-byte pad before the key"
    assert hit.key_offset == 64, "relative to the window start, not absolute"
    assert hit.key_absolute_offset == 256
    assert hit.key_length == 32
    assert hit.length == 160
    assert hit.key_hex == ref[256:288].hex()


@requires_vol3_import
def test_verify_key_recovered_is_true_for_the_real_key_bytes(tmp_path):
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "KeyRecovered")
    assert verify_key_recovered(source, ref, ref[256:288]) is True
    assert verify_key_recovered(source, ref, b"\xff" * 32) is False


@requires_vol3_import
def test_expected_offset_membership_is_exact_not_fuzzy(tmp_path):
    """One byte off is a MISS, deliberately.

    The failure mode this instrument exists to catch is "reported a hit 64 bytes
    from the real key". A tolerance would score that as a near-miss and let the
    harness report success for a plugin that points at the wrong bytes.
    """
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "ExactMembership")
    assert run_over_buffer(source, ref, expected_offset=256).expected_offset_reported
    assert not run_over_buffer(source, ref, expected_offset=257).expected_offset_reported


@requires_vol3_import
def test_load_plugin_class_rejects_a_source_with_no_plugin(tmp_path):
    with pytest.raises(CapabilityError) as excinfo:
        load_plugin_class("X = 1\n", "memdiver_test_no_plugin_class")
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT


@requires_vol3_import
def test_load_plugin_class_does_not_leave_a_broken_module_behind():
    """A failed exec must not poison ``sys.modules`` for the next load."""
    import sys

    name = "memdiver_test_failed_exec"
    with pytest.raises(ZeroDivisionError):
        load_plugin_class("1 / 0\n", name)
    assert name not in sys.modules


def test_capability_error_when_the_extra_is_absent(monkeypatch):
    """With the extra gone, every entry point raises the ONE capability error."""
    from memdiver.engine import vol3_verify

    monkeypatch.setattr(vol3_verify, "HAS_VOLATILITY3", False)
    for call in (
        lambda: vol3_verify.framework_version(),
        lambda: vol3_verify.load_plugin_class("X = 1\n", "m"),
        lambda: vol3_verify.run_over_buffer("X = 1\n", b""),
        lambda: vol3_verify.run_over_file("X = 1\n", Path("/nonexistent")),
    ):
        with pytest.raises(CapabilityError) as excinfo:
            call()
        assert excinfo.value.category is ErrorCategory.UNSUPPORTED
        assert 'memdiver[vol]' in str(excinfo.value)


# --------------------------------------------------------------------------- #
# B5.2 bug (b): the --pid path
#
# WHAT IS PROVABLE HERE, and what is not.
#
# Provable: the declared requirement set (pinned in tests/test_vol3_emit.py and
# tests/test_volatility3_exporter.py via ``emitted_requirements``); that the
# plugin still validates and scans with NO kernel module, which is what
# ``optional=True`` on the ModuleRequirement buys; that vol3's own KernelModule
# automagic does not skip an optional ModuleRequirement; that the failure is
# LOUD; and the argument SHAPE handed to ``list_tasks``/``list_processes``.
#
# NOT provable here: ``proc.add_process_layer()`` and the scan that follows it.
# That needs a real kernel memory image plus a matching ISF, and neither this
# repository nor this machine has one. So PID *narrowing* itself remains
# unproven -- see CHANGELOG.md. Nothing below should be read as end-to-end PID
# coverage.
# --------------------------------------------------------------------------- #

@requires_vol3_import
def test_kernel_module_automagic_does_not_skip_optional_requirements():
    """Why ``optional=True`` on the ``kernel`` ModuleRequirement still gets FILLED.

    The template declares ``kernel`` optional because a MANDATORY
    ``ModuleRequirement`` would make ``PluginInterface.__init__`` fail its
    requirement gate on exactly the flat process dumps this plugin exists to
    scan: ``ConfigurableInterface.unsatisfied`` skips optional requirements, so
    optional is the only way the plugin loads at all without a kernel image.

    The obvious worry is that optional therefore means "never filled". It does
    not, and this is a source-level pin on the reason:
    ``framework/automagic/module.py``'s ``KernelModule.__call__`` calls
    ``requirement.unsatisfied(...)`` on the ModuleRequirement DIRECTLY, and never
    consults ``requirement.optional`` -- the optional-skip lives in
    ``unsatisfied_children`` / ``ConfigurableInterface.unsatisfied``, which the
    automagic does not go through. So when a kernel image plus symbols exist the
    automagic fills it; otherwise ``requirements.ModuleRequirement``'s
    ``default=False`` leaves it falsy and ``_pid_scan`` returns ``None``.

    Asserted against Volatility3's own source rather than end-to-end because
    filling it for real requires a kernel memory image and a matching ISF, which
    this repository does not have.
    """
    import inspect

    from volatility3.framework.automagic import module as vol3_automagic_module

    source = inspect.getsource(vol3_automagic_module.KernelModule.__call__)
    assert "requirement.unsatisfied(" in source, (
        "KernelModule stopped calling unsatisfied() on the requirement itself; "
        "an optional ModuleRequirement may no longer be filled by automagic"
    )
    assert "unsatisfied_children" not in source
    assert "optional" not in source, (
        "KernelModule gained an `optional` check; the emitted plugin's optional "
        "`kernel` requirement may now be skipped by the automagic"
    )
    # And the default really is falsy, which is what `_pid_scan` branches on.
    from volatility3.framework.configuration import requirements as vol3_requirements

    signature = inspect.signature(vol3_requirements.ModuleRequirement.__init__)
    assert signature.parameters["default"].default is False


@requires_vol3_import
def test_plugin_validates_and_scans_with_no_kernel_module(tmp_path):
    """A flat dump has no kernel module, and the plugin must still work.

    This is the whole justification for ``optional=True``: with ``--pid`` asked
    for and ``config["kernel"]`` falsy, construction must not raise (Volatility3
    runs ``unsatisfied()`` in ``PluginInterface.__init__``) and the scan must
    still happen and still report the key.
    """
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "NoKernel")
    report = run_over_buffer(
        source, ref, expected_offset=256,
        extra_config={"pid": 1234, "full_scan": False},
    )
    assert report.match_count == 1, report.to_dict()
    assert report.expected_offset_reported is True


@requires_vol3_import
def test_pid_that_cannot_be_honoured_is_LOUD_not_silent(tmp_path, caplog):
    """The entire difference between "silently wrong" and "wrong but told you".

    Before B5.2 ``--pid`` was dead code wrapped in ``except Exception: continue``
    and a whole-layer scan was reported as if it were PID-restricted. The scan
    still falls back -- that degrade is deliberate -- but it now says so at
    WARNING, which ``vol`` surfaces on stderr by default.
    """
    import logging

    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "LoudPid")
    with caplog.at_level(logging.WARNING):
        run_over_buffer(
            source, ref, extra_config={"pid": 4242, "full_scan": False},
        )
    warnings = [
        record.getMessage() for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert any("could NOT be honoured" in message for message in warnings), warnings
    assert any("4242" in message for message in warnings), warnings
    assert any(
        "not restricted to that process" in message for message in warnings
    ), warnings


@requires_vol3_import
def test_pid_scan_passes_a_module_name_and_a_callable_filter(tmp_path, monkeypatch):
    """The ARGUMENT SHAPE, provable with no kernel image at all.

    Volatility3 2.27.x wants::

        linux   PsList.list_tasks(context, vmlinux_module_name, filter_func, ...)
        windows PsList.list_processes(context, kernel_module_name, filter_func)

    The pre-B5.2 template called them as ``(self.context, layer_name, stab)``:
    argument 2 was a TRANSLATION-LAYER name, which raises
    ``KeyError: 'primary'`` inside ``context.modules[...]``, and argument 3 was a
    symbol-table *string* landing in ``filter_func``, which raises ``TypeError:
    'str' object is not callable``. Both were swallowed by ``except Exception:
    continue``, so ``--pid`` silently scanned everything.

    Injecting a stub ``pslist`` module lets the call be observed without a kernel
    image: the recorded second argument must be the MODULE name from
    ``config["kernel"]``, and the third must be the CALLABLE that the PsList's
    own ``create_pid_filter`` factory returned for exactly this PID. A regression
    to the old form fails this test rather than degrading in the field.

    (The stub's ``list_tasks`` yields nothing, so the windows branch is tried
    next and legitimately raises ``KeyError`` on the absent module -- which also
    exercises the narrowed swallow.)
    """
    import sys
    import types as pytypes

    recorded: dict = {}

    stub = pytypes.ModuleType("volatility3.plugins.linux.pslist")

    class PsList:
        @classmethod
        def create_pid_filter(cls, pid_list=None):
            recorded["filter_pids"] = list(pid_list or [])
            wanted = set(recorded["filter_pids"])

            def filter_func(proc):
                # vol3's own factories filter OUT non-matches; mirror that so a
                # future reader does not "helpfully" invert it.
                return getattr(proc, "pid", None) not in wanted

            return filter_func

        @classmethod
        def list_tasks(
            cls, context, vmlinux_module_name,
            filter_func=lambda _: False, include_threads=False,
        ):
            recorded["call"] = (context, vmlinux_module_name, filter_func)
            return iter(())

    stub.PsList = PsList
    monkeypatch.setitem(sys.modules, "volatility3.plugins.linux.pslist", stub)

    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "PidShape")
    report = run_over_buffer(
        source, ref, expected_offset=256,
        extra_config={"pid": 4242, "full_scan": False, "kernel": "kernel"},
    )

    assert "call" in recorded, "the emitted plugin never called list_tasks"
    _context, module_name, filter_func = recorded["call"]
    assert module_name == "kernel", (
        "argument 2 must be the MODULE name from config['kernel']; the old "
        f"template passed the translation-layer name, got {module_name!r}"
    )
    assert callable(filter_func), (
        "argument 3 must be a filter CALLABLE; the old template passed a "
        f"symbol-table string, got {filter_func!r}"
    )
    assert recorded["filter_pids"] == [4242], (
        "the filter must come from create_pid_filter([pid]) -- the plugin no "
        "longer does its own proc.pid == pid comparison"
    )
    # The filter really does filter, so nobody 'simplifies' it away later.
    class _Proc:
        def __init__(self, pid):
            self.pid = pid
    assert filter_func(_Proc(4242)) is False
    assert filter_func(_Proc(1)) is True

    # And, the PID path having yielded nothing, the whole-layer fallback ran.
    assert report.match_count == 1, report.to_dict()
    assert report.expected_offset_reported is True


# --------------------------------------------------------------------------- #
# B5.2 bug (c): WHICH layer gets scanned
# --------------------------------------------------------------------------- #

def _stacked_context(data: bytes, exposed: int):
    """A two-layer stack reproducing the ``Elf64Layer`` failure mode.

    ``base_layer`` is a complete ``BufferDataLayer`` over *data*; ``primary`` is
    a translation layer that maps only the first *exposed* bytes of it. That is
    the measured shape ``LayerStacker`` produces for a MemDiver dump: layers come
    out ``['base_layer', 'primary']`` where ``base_layer`` is a ``FileLayer`` over
    the full 11,223,040 bytes and ``primary`` is an ``Elf64Layer`` exposing about
    6 KB (``max 0x232b``) -- because MemDiver's raw dumps begin with
    ``7f 45 4c 46`` and have ``e_type = ET_DYN``, so they LOOK like an ELF while
    carrying no PT_LOAD table covering the dump.

    Modelled with a hand-written translation layer rather than a real
    ``Elf64Layer`` so the proof runs in CI with no corpus. The out-of-process
    twin of this test, against the real ``vol`` and the real ELF-headed dump,
    lives in ``tests/test_vol3_subproc.py``.
    """
    from volatility3.framework import contexts as vol3_contexts
    from volatility3.framework import exceptions as vol3_exceptions
    from volatility3.framework import interfaces as vol3_ifaces
    from volatility3.framework.layers import physical as vol3_physical

    class TruncatedTranslationLayer(vol3_ifaces.layers.TranslationLayerInterface):
        """Maps only ``[0, exposed)`` of ``base_layer``, one-to-one."""

        @property
        def minimum_address(self) -> int:
            return 0

        @property
        def maximum_address(self) -> int:
            return exposed - 1

        @property
        def dependencies(self):
            return ["base_layer"]

        def is_valid(self, offset: int, length: int = 1) -> bool:
            return 0 <= offset and offset + length - 1 <= self.maximum_address

        def mapping(self, offset: int, length: int, ignore_errors: bool = False):
            if not self.is_valid(offset, length):
                if ignore_errors:
                    return
                raise vol3_exceptions.InvalidAddressException(
                    self.name, offset, "beyond the mapped window",
                )
            yield (offset, length, offset, length, "base_layer")

    context = vol3_contexts.Context()
    context.add_layer(
        vol3_physical.BufferDataLayer(context, "base", "base_layer", data),
    )
    context.add_layer(TruncatedTranslationLayer(context, "trans", "primary"))
    return context


def _run_in_context(source: str, context, module_name: str, **extra):
    """Construct the emitted plugin against *context* and return its rows."""
    plugin_cls = load_plugin_class(source, module_name)
    config_path = f"plugins.{plugin_cls.__name__}"
    context.config[f"{config_path}.primary"] = "primary"
    context.config[f"{config_path}.full_scan"] = True
    for key, value in extra.items():
        context.config[f"{config_path}.{key}"] = value
    grid = plugin_cls(context, config_path).run()
    index = _column_index(grid)
    return [int(row[index["KeyOffset"]]) for row in _rows(grid)]


#: A key deliberately placed OUTSIDE the truncated translation layer's window,
#: so "scanned the wrong layer" and "scanned the right layer" give different
#: answers rather than both giving one hit.
_STACK_SIZE = 8192
_STACK_EXPOSED = 1024
_STACK_KEY_OFFSET = 4096


@requires_vol3_import
def test_default_scan_target_is_the_lowest_layer(tmp_path):
    """Bug (c): the default scan target is now the LOWEST layer, not ``primary``.

    Measured before the fix, two independent ways:

    1. In-process through ``automagic``, ``primary`` binds to an ``Elf64Layer``
       exposing ~6 KB (``max 0x232b``) of an 11,223,040-byte dump, so the plugin
       scanned ~6 KB of 11 MB.
    2. Out-of-process, the real ``vol`` printed "Scan Failure: Sections have no
       size, nothing to scan" and the pad-128 plugin that finds the key in 0.02 s
       in-process returned ``[]``.

    Walking ``layer.dependencies`` to the bottom fixes both; the out-of-process
    half is now proved for real in
    ``tests/test_vol3_subproc.py::test_run_plugin_over_the_real_dump_finds_the_key_through_real_vol``.
    This test is the CI-runnable model of the in-process half: the key sits at
    4,096, beyond the 1,024-byte window the translation layer exposes, so only a
    scan of the lowest layer can find it.

    Flipping the default is the right call: nobody can be relying on the old
    behaviour, because the old behaviour was zero hits where the key
    demonstrably is.
    """
    ref, _hit, _ = synth_hit(ref_size=_STACK_SIZE, key_offset=_STACK_KEY_OFFSET)
    source = emit_for(
        ref, _STACK_KEY_OFFSET, 32, 64, tmp_path, "LowestLayer",
    )
    found = _run_in_context(
        source, _stacked_context(ref, _STACK_EXPOSED), "memdiver_test_lowest_layer",
    )
    assert found == [_STACK_KEY_OFFSET], found


@requires_vol3_import
def test_virtual_opts_back_into_the_translation_layer(tmp_path):
    """``--virtual`` is a real switch, and this is the control for the test above.

    Scanning the translation layer is correct for a genuine kernel image, where
    virtual addresses are what the analyst wants reported. On this stack it finds
    nothing -- which is exactly what the unfixed template did unconditionally,
    and is what makes the previous test a measurement rather than a restatement.
    """
    ref, _hit, _ = synth_hit(ref_size=_STACK_SIZE, key_offset=_STACK_KEY_OFFSET)
    source = emit_for(
        ref, _STACK_KEY_OFFSET, 32, 64, tmp_path, "VirtualLayer",
    )
    found = _run_in_context(
        source, _stacked_context(ref, _STACK_EXPOSED),
        "memdiver_test_virtual_layer", virtual=True,
    )
    assert found == [], found


@requires_vol3_import
def test_a_single_flat_layer_is_unaffected_by_the_walk(tmp_path):
    """The walk must be a no-op when there is nothing below ``primary``.

    ``run_over_buffer``/``run_over_file`` register ONE flat layer with no
    dependencies, which is how every other test in this file scans. If the walk
    ever wandered off that layer, the selectivity numbers below would move for a
    reason that has nothing to do with the pattern.
    """
    ref, _hit, _ = synth_hit()
    source = emit_for(ref, 256, 32, 64, tmp_path, "FlatWalk")
    report = run_over_buffer(source, ref, expected_offset=256)
    assert report.layer_scanned == "flat"
    assert report.match_count == 1
    assert report.expected_offset_reported is True


# --------------------------------------------------------------------------- #
# Selectivity, on the real dump
#
# `requires_dataset`, NOT `slow`: the scan is ~0.02 s over 11 MB, and `slow` is
# deselected by `addopts`, which would hide these from the only developer who
# actually has the corpus.
#
# Both tests are independent of bugs (a)/(b)/(c). Selectivity is a property of
# the emitted PATTERN -- how many distinct byte values its anchor carries --
# not of how the plugin imports, which layer it picks, or how it filters by PID.
# That independence is why they can be written now, against the unfixed
# template, and stay meaningful after B5.1/B5.2 change it.
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
@requires_vol3_import
def test_the_real_key_sits_inside_a_long_zero_run(tmp_path):
    """The measured premise the two selectivity tests rest on.

    If this fails, the corpus is not the one the numbers below were measured
    against and those numbers mean nothing -- so it is asserted separately
    rather than assumed.
    """
    dump = real_dump()
    assert dump.stat().st_size == REAL_DUMP_BYTES
    data = dump.read_bytes()

    start = REAL_KEY_OFFSET
    while start > 0 and data[start - 1] == 0:
        start -= 1
    end = REAL_KEY_OFFSET + REAL_KEY_LENGTH
    while end < len(data) and data[end] == 0:
        end += 1
    assert (start, end) == ZERO_RUN, (start, end)


@pytest.mark.requires_dataset
@requires_vol3_import
def test_emitted_plugin_is_selective_at_a_widened_pad(tmp_path):
    """At pad 128 the emitted plugin is a real detector: exactly one hit, correct.

    128 bytes either side reaches past the 71-byte zero preamble into genuine
    struct bytes, so the anchor carries 18 distinct values instead of 1 -- and
    the match count collapses from 5,311 to 1 over the same 11 MB.
    """
    dump = real_dump()
    data = dump.read_bytes()
    source = emit_for(data, REAL_KEY_OFFSET, REAL_KEY_LENGTH, 128, tmp_path, "Pad128")

    report = run_over_file(source, dump, expected_offset=REAL_KEY_OFFSET)

    assert report.match_count == 1, report.to_dict()
    assert report.expected_offset_reported is True
    assert report.anchor_distinct_bytes == 18, report.anchor_distinct_bytes
    assert report.hits[0].key_hex == data[
        REAL_KEY_OFFSET:REAL_KEY_OFFSET + REAL_KEY_LENGTH
    ].hex()

    truth = TruthInterval(
        start=REAL_KEY_OFFSET, length=REAL_KEY_LENGTH, secret_type="TLS12_MASTER",
        key_hex=report.hits[0].key_hex, client_random="", source="keylog",
    )
    scored = score_intervals(report.hits, [truth])
    assert scored["containment"].precision == 1.0
    assert scored["containment"].recall == 1.0


@pytest.mark.requires_dataset
@requires_vol3_import
def test_emitted_plugin_is_NOT_selective_at_the_default_pad(tmp_path):
    """CHARACTERIZATION: at the default pad 64 the emitted plugin is unusable.

    The key's enclosing all-zero run is only 71 bytes long on the leading side,
    so at pad 64 the entire 176-byte window lies inside it: the regex degenerates
    to ``\\x00{64}.{48}\\x00{64}`` and matches on a stride-176 lattice wherever a
    long zero run exists. Measured on this 11 MB dump: 5,311 matches, one of
    which is the key.

    **Asserting the bad number is the point.** A skip or an xfail here would
    leave "about five thousand" as folklore; an assertion makes 5,311 a tracked
    baseline that can neither drift upward unnoticed nor improve unnoticed.

    If this test starts FAILING, the emitter got better. Delete it deliberately,
    with a CHANGELOG entry recording the before/after -- do not relax the bound.
    """
    dump = real_dump()
    data = dump.read_bytes()
    source = emit_for(data, REAL_KEY_OFFSET, REAL_KEY_LENGTH, 64, tmp_path, "Pad64")

    report = run_over_file(source, dump, expected_offset=REAL_KEY_OFFSET)

    assert report.anchor_distinct_bytes == 1, (
        "the whole anchor is one repeated byte value (0x00); this single number "
        "predicts the blow-up better than the static ratio does"
    )
    assert report.anchor_bytes == 128
    assert report.match_count == 5311, report.match_count
    assert report.match_count > 1000
    assert report.expected_offset_reported is True, (
        "the key IS among the hits -- recall is fine, precision is the disaster"
    )

    truth = TruthInterval(
        start=REAL_KEY_OFFSET, length=REAL_KEY_LENGTH, secret_type="TLS12_MASTER",
        key_hex=data[REAL_KEY_OFFSET:REAL_KEY_OFFSET + REAL_KEY_LENGTH].hex(),
        client_random="", source="keylog",
    )
    scored = score_intervals(report.hits, [truth])
    assert scored["containment"].recall == 1.0
    assert scored["containment"].precision < 0.001, scored["containment"].precision


@pytest.mark.requires_dataset
@requires_vol3_import
def test_static_ratio_alone_does_not_predict_selectivity(tmp_path):
    """Why ``anchor_distinct_bytes`` is a reported field.

    Pad 64 has a static ratio of 0.727 -- comfortably above the emitter's 0.3
    floor -- and 5,311 matches. Pad 512 has a similar *kind* of ratio and one
    match. The ratio says how much of the window is pinned; only the number of
    distinct anchor values says whether pinning it means anything.
    """
    dump = real_dump()
    data = dump.read_bytes()
    reports = {}
    for pad in (64, 512):
        source = emit_for(
            data, REAL_KEY_OFFSET, REAL_KEY_LENGTH, pad, tmp_path, f"Ratio{pad}",
        )
        reports[pad] = run_over_file(source, dump, expected_offset=REAL_KEY_OFFSET)

    assert reports[64].hits[0].static_ratio == pytest.approx(0.7273, abs=1e-3)
    assert reports[64].anchor_distinct_bytes == 1
    assert reports[64].match_count > 1000

    assert reports[512].hits[0].static_ratio > 0.9
    assert reports[512].anchor_distinct_bytes == 74, reports[512].anchor_distinct_bytes
    assert reports[512].match_count == 1
    assert reports[512].expected_offset_reported is True
