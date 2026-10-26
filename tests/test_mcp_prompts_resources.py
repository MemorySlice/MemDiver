"""MCP prompts (playbooks) and resources (case state) — P6 T6.1.

Structural guard: every ``tool_name(...)`` a prompt cites in backticks must be a
registered tool, so a rename or a typo in a playbook fails here.

Signature guard: a citation that names at least one keyword must use only real
parameters of that tool and must name ALL its required parameters, unless its
any top-level argument is the bare continuation marker ``...`` ("and the
rest"). Citations with no keyword at all (``case_query(``) are exempt.
"""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote

import pytest

pytest.importorskip("mcp")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.core import path_sandbox  # noqa: E402
from memdiver.isf.draft import IsfDraftStore, Provenance  # noqa: E402
from memdiver.mcp_server.server import create_server  # noqa: E402

CAP = "a" * 64
PROMPTS = {
    "memdiver_start", "vol3_inside_memdiver", "vol3_plugin_dev", "isf_workbench",
    "image_to_process_keys", "n_image_variance", "object_model_from_keylog", "code_evidence",
}
TEMPLATES = {
    "memdiver://case/{case_dir}/schema", "memdiver://case/{case_dir}/manifest",
    "memdiver://case/{case_dir}/annotations/{capture}",
    "memdiver://case/{case_dir}/isf/{capture}/{draft}",
}
TOOL_CALL = re.compile(r"`([a-z][a-z0-9_]*)\(")


@pytest.fixture(scope="module")
def server():
    return create_server()


@pytest.fixture
def case_dir(tmp_path):
    case = Case.init(tmp_path / "case")
    store = IsfDraftStore(case.dir)
    store.create(CAP, "d1", arch="x86_64")
    store.set_symbol(CAP, "d1", "init_task", 0x1000, Provenance("kallsyms", "manual"))
    return str(case.dir)


def _read(server, case_dir, tail):
    uri = f"memdiver://case/{quote(case_dir, safe='')}/{tail}"
    return json.loads(list(asyncio.run(server.read_resource(uri)))[0].content)


def _render(server, name, args=None):
    result = asyncio.run(server.get_prompt(name, args or {}))
    return "\n".join(m.content.text for m in result.messages)


def test_prompts_listed(server):
    assert {p.name for p in asyncio.run(server.list_prompts())} == PROMPTS


def test_resource_templates_listed(server):
    assert {t.uri_template for t in asyncio.run(server.list_resource_templates())} == TEMPLATES


def test_tool_count_unchanged(server):
    assert len(asyncio.run(server.list_tools())) == 120


@pytest.mark.parametrize("name", sorted(PROMPTS))
def test_every_prompt_renders_with_and_without_arguments(server, name):
    bare = _render(server, name)
    assert len(bare) > 400
    declared = [a.name for a in next(
        p for p in asyncio.run(server.list_prompts()) if p.name == name).arguments or []]
    if declared:
        filled = _render(server, name, {a: f"<<{a}>>" for a in declared})
        assert f"<<{declared[0]}>>" in filled


def test_every_tool_named_in_a_prompt_is_registered(server):
    tools = {t.name for t in asyncio.run(server.list_tools())}
    cited = {}
    for name in PROMPTS:
        for tool in TOOL_CALL.findall(_render(server, name)):
            cited.setdefault(tool, name)
    assert len(cited) > 40
    assert {t: p for t, p in cited.items() if t not in tools} == {}


def _split_args(text, start):
    """Top-level comma-split args of the call whose ``(`` precedes ``start``."""
    depth, args, cur = 1, [], ""
    for ch in text[start:]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                break
        if ch == "," and depth == 1:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    args.append(cur.strip())
    return [a for a in args if a]


def _citations(server):
    """Yield (prompt, tool, citation, keywords, has_marker) for every rendered call."""
    renders = []
    for name in sorted(PROMPTS):
        declared = [a.name for a in next(
            p for p in asyncio.run(server.list_prompts()) if p.name == name).arguments or []]
        renders.append((name, _render(server, name)))
        if declared:
            renders.append((name, _render(server, name, {a: f"<<{a}>>" for a in declared})))
    for name, text in renders:
        for m in TOOL_CALL.finditer(text):
            args = _split_args(text, m.end())
            kws = [k.group(1) for a in args if (k := re.match(r"([a-z_][a-z0-9_]*)\s*=(?!=)", a))]
            yield name, m.group(1), text[m.start() + 1:m.end() + 60].split("`")[0], kws, \
                "..." in args


def test_every_prompt_citation_matches_the_tool_signature(server):
    schemas = {t.name: t.input_schema for t in asyncio.run(server.list_tools())}
    checked, errors = 0, []
    for prompt, tool, cite, kws, marker in _citations(server):
        if tool not in schemas or not kws:
            continue
        checked += 1
        props = set(schemas[tool].get("properties", {}))
        required = set(schemas[tool].get("required", []))
        unknown = sorted(set(kws) - props)
        missing = [] if marker else sorted(required - set(kws))
        if unknown or missing:
            errors.append(f"[{prompt}] {tool}: {cite!r} unknown={unknown} missing={missing}")
    assert checked > 40
    assert errors == [], "\n" + "\n".join(errors)


def test_manifest_resource_has_real_content(server, case_dir):
    body = _read(server, case_dir, "manifest")
    assert body["name"] == "case"
    assert "d1" in json.dumps(body["isf"])


def test_schema_resource_still_served(server, case_dir):
    assert _read(server, case_dir, "schema") == Case.open(case_dir).schema()


def test_annotations_resource_lists_capture(server, case_dir):
    body = _read(server, case_dir, f"annotations/{CAP}")
    assert body["capture_id"] == CAP and body["count"] == len(body["entries"]) >= 1


def test_isf_draft_resource_returns_the_draft(server, case_dir):
    body = _read(server, case_dir, f"isf/{CAP}/d1")
    assert "error" not in body and "d1" in json.dumps(body)


def test_missing_case_is_a_structured_error(server, tmp_path):
    body = _read(server, str(tmp_path / "nope"), "manifest")
    assert "error" in body


@pytest.fixture
def sandboxed(tmp_path, monkeypatch):
    from memdiver.api.config import get_settings
    ok = tmp_path / "ok"
    ok.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(ok))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(ok))
    get_settings.cache_clear()
    yield ok
    get_settings.cache_clear()


@pytest.mark.parametrize("tail", ["manifest", "schema", f"annotations/{CAP}", f"isf/{CAP}/d1"])
def test_sandbox_on_denies_resource_outside_roots(server, case_dir, sandboxed, tail):
    body = _read(server, case_dir, tail)
    assert body.get("code") == "path.outside_sandbox"


def test_sandbox_on_admits_resource_inside_roots(server, sandboxed):
    inside = Case.init(sandboxed / "case")
    body = _read(server, str(inside.dir), "manifest")
    assert body.get("code") != "path.outside_sandbox" and body["name"] == "case"
