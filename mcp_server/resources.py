"""MCP resources: read-only case state (P6 T6.1), behind the read sandbox.

``MCPServer`` resources are not tools, so ``path_guard.guard_tool`` never sees
them (the original ``case_schema`` resource bypassed the sandbox). Every
resource here runs :func:`path_guard.denial_for` on its arguments first and
returns the SAME structured JSON error a denied tool call would.

URIs (URL-encode the case directory):
``memdiver://case/{case_dir}/manifest``, ``.../schema``,
``.../annotations/{capture}``, ``.../isf/{capture}/{draft}``.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from memdiver.core import path_sandbox
from memdiver.core.service_errors import CapabilityError

from .path_guard import _roots
from .presenters import present_inspect_mcp_call


def _read_denial(session: Any, arguments: dict) -> Optional[CapabilityError]:
    """The READ-sandbox denial for the resource's path arguments (``None`` = admitted).

    Same walker and roots as ``path_guard.denial_for`` minus its write-root
    check: resources only read, so a case under a read root is admitted.
    """
    roots = _roots(getattr(session, "dataset_root", None))
    if not roots:
        return None
    try:
        path_sandbox.check_arguments(dict(arguments), roots)
    except CapabilityError as err:
        return err
    return None


def _render(session: Any, produce: Callable, **arguments: Any) -> str:
    """Sandbox-check ``arguments`` (named as the tool parameters are), then produce JSON."""
    denied = _read_denial(session, arguments)
    if denied is not None:
        return json.dumps(denied.to_dict(), default=str)
    return json.dumps(present_inspect_mcp_call(produce), default=str)


def register_resources(mcp, session: Optional[Any] = None) -> None:
    """Register the case resources on an ``MCPServer`` instance."""
    from mcp.server.mcpserver import ResourceSecurity

    from memdiver.app import tools_annotations, tools_case, tools_isf

    # A case directory is legitimately an absolute path; ".." and NUL stay rejected.
    case_security = ResourceSecurity(reject_absolute_paths=False)

    @mcp.resource("memdiver://case/{case_dir}/schema",
                  name="case_schema", mime_type="application/json",
                  description="Schema of a case; URL-encode the case directory.",
                  security=case_security)
    def case_schema_resource(case_dir: str) -> str:
        return _render(session,
                       lambda: tools_case.case_schema_result(case_dir), case_dir=case_dir)

    @mcp.resource("memdiver://case/{case_dir}/manifest",
                  name="case_manifest", mime_type="application/json",
                  description="Inventory of a case: views, images, captures, annotations, ISF, plugins.",
                  security=case_security)
    def case_manifest_resource(case_dir: str) -> str:
        return _render(session,
                       lambda: tools_case.case_manifest_result(
                           case_dir, read_roots=_roots(getattr(session, "dataset_root", None))),
                       case_dir=case_dir)

    @mcp.resource("memdiver://case/{case_dir}/annotations/{capture}",
                  name="case_annotations", mime_type="application/json",
                  description="Current annotations of one capture of a case.",
                  security=case_security)
    def case_annotations_resource(case_dir: str, capture: str) -> str:
        return _render(session,
                       lambda: tools_annotations.annotations_list_result(case_dir, capture),
                       case_dir=case_dir, capture_id=capture)

    @mcp.resource("memdiver://case/{case_dir}/isf/{capture}/{draft}",
                  name="case_isf_draft", mime_type="application/json",
                  description="Materialized summary of one ISF draft (capture + draft name).",
                  security=case_security)
    def case_isf_draft_resource(case_dir: str, capture: str, draft: str) -> str:
        return _render(session,
                       lambda: tools_isf.isf_draft_get_result(case_dir, capture, draft),
                       case_dir=case_dir, capture_id=capture)
