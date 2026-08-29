"""Shared helpers for the emitted-artifact pins (vol3 plugin / YARA rule).

Two helpers live here because more than one test module needs them and a
copy-pasted third instance is how a pin quietly stops pinning:

* :func:`synth_hit` — the corpus-independent synthetic hit every emission test
  builds on. It derives its neighborhood from
  ``engine.brute_force.DEFAULT_NEIGHBORHOOD_PAD`` rather than a local ``64``
  literal, so moving the default default-pad shows up in the emitted artifacts
  instead of sailing past a green suite.
* :func:`strip_timestamp` — neutralises the UTC ``Generated:`` line the vol3
  exporter embeds (``architect.volatility3_exporter``), the exporter's only
  source of nondeterminism, so two emissions are byte-comparable.
* :func:`emitted_requirements` — parses the emitted plugin's
  ``get_requirements`` block with the AST, so a pin on one requirement can no
  longer be satisfied by a substring belonging to another. Its docstring names
  the two vacuous tests it replaced.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Tuple

import numpy as np

from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD


def strip_timestamp(text: str) -> str:
    """Neutralize the UTC timestamp the vol3 exporter embeds so two runs of
    ``emit_plugin`` are byte-comparable."""
    return re.sub(r"Generated: \S+", "Generated: X", text)


def synth_hit(
    ref_size: int = 1024,
    key_offset: int = 256,
    key_length: int = 32,
    neighborhood_pad: int = DEFAULT_NEIGHBORHOOD_PAD,
) -> Tuple[bytes, Dict[str, object], int]:
    """A synthetic hit whose anchor is healthy *by construction*.

    ``neighborhood_pad`` static bytes of preamble, ``key_length`` volatile key
    bytes, ``neighborhood_pad`` static bytes of trailer — so the emitted window
    is ``pad + key_length + pad`` and the static ratio always clears
    ``min_static_ratio``. The pad defaults to the shipped
    :data:`DEFAULT_NEIGHBORHOOD_PAD`; pass a different one to exercise the knob.

    Returns ``(reference_bytes, hit_dict, neighborhood_length)``.
    """
    np.random.seed(3)
    ref = bytearray(np.random.randint(0, 256, ref_size, dtype=np.uint8).tobytes())
    nb_start = max(0, key_offset - neighborhood_pad)
    # The real slicer clamps at 0 / len(state); mirror the leading clamp so a
    # pad wider than ``key_offset`` still describes a self-consistent window.
    lead = key_offset - nb_start
    nb_variance: List[float] = (
        [100.0] * lead              # static struct preamble
        + [15000.0] * key_length    # volatile key region
        + [50.0] * neighborhood_pad  # static struct trailer
    )
    nb_len = len(nb_variance)
    hit: Dict[str, object] = {
        "offset": key_offset,
        "length": key_length,
        "neighborhood_start": nb_start,
        "neighborhood_variance": nb_variance,
    }
    return bytes(ref), hit, nb_len


def _requirement_kind(call: ast.Call) -> str:
    """``requirements.IntRequirement(...)`` -> ``"Int"``.

    The ``Requirement`` suffix is dropped because it is noise repeated on every
    row of the pin; what distinguishes the entries is ``Int`` vs ``Boolean`` vs
    ``TranslationLayer``.
    """
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name[: -len("Requirement")] if name.endswith("Requirement") else name


def _keyword_value(node: ast.expr) -> object:
    """Literal value of a keyword argument, or its source text when not literal."""
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return ast.unparse(node)


def emitted_requirements(source: str) -> Dict[str, Dict[str, object]]:
    """Parse an emitted vol3 plugin's ``get_requirements`` into a real mapping.

    Returns ``{name: {"kind", "optional", "default", "has_default"}}`` in
    declaration order. ``has_default`` is carried separately because a
    requirement that *omits* ``default=`` and one that spells ``default=None``
    are different statements about the template, and collapsing both to ``None``
    would let one silently become the other.

    **Why this exists.** Two tests used to pin the emitted requirement block
    with substring assertions over a ~7 KB generated file, and both were
    vacuous for the same reason -- a substring can match a *different* line:

    * ``tests/test_vol3_emit.py::test_emit_pid_required`` asserted
      ``'name="pid"' in src`` **and** ``"optional=False" in src``, then claimed
      in its name and docstring that ``pid`` was non-optional. ``pid`` is
      ``optional=True``; the ``optional=False`` that satisfied the assertion
      belongs to the ``TranslationLayerRequirement`` on ``primary``, a different
      requirement entirely. Name, docstring and assertion all disagreed with the
      code, and the test passed.
    * ``tests/test_volatility3_exporter.py::test_export_pid_requirement``
      asserted ``"pid_filter" in source or "pid" in source`` immediately after
      ``assert '"pid"' in source`` -- the right operand of the ``or`` was
      unconditionally true, so the whole line asserted nothing new.

    Parsing the AST fixes the *class* of bug rather than the two instances: an
    assertion about ``pid`` can no longer be satisfied by a line about
    ``primary``.
    """
    tree = ast.parse(source)
    requirements: Dict[str, Dict[str, object]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "get_requirements":
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            keywords = {
                kw.arg: kw.value for kw in call.keywords if kw.arg is not None
            }
            if "name" not in keywords:
                continue
            name = _keyword_value(keywords["name"])
            entry: Dict[str, object] = {"kind": _requirement_kind(call)}
            entry["optional"] = (
                _keyword_value(keywords["optional"]) if "optional" in keywords else None
            )
            entry["has_default"] = "default" in keywords
            entry["default"] = (
                _keyword_value(keywords["default"]) if "default" in keywords else None
            )
            requirements[str(name)] = entry
    return requirements
