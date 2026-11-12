"""Runtime for oracle sources inlined into a single-file plugin.

The inliner (``memdiver.oracles.embed``) copies this module's source verbatim
into every generated plugin, so the plugin and the repository run the same
code to find, integrity-check and load inlined oracles. Therefore it follows
the same paste-safe contract as the format modules: standard library only,
no relative imports, no ``__file__``, no ``from __future__``, Python 3.8+.

Block format. Each inlined source sits between two marker lines that start in
column 0 and carry a role (``oracle``, ``primitive`` or ``runtime``), a name
and the SHA-256 of the exact text between the two markers (UTF-8). For a
module copied whole, that is the SHA-256 of the module file itself, so
anyone can match a block against the repository with ``sha256sum``::

    # --- memdiver oracle:gocryptfs-gcm sha256=<64 hex> begin ---
    <verbatim module source>
    # --- memdiver oracle:gocryptfs-gcm sha256=<64 hex> end ---

Namespacing. Several oracles and primitives can be inlined into one plugin,
and their module-level names (``KIND``, ``build_oracle``, helpers) would
collide in a shared namespace. So a plugin keeps the blocks inside one raw
string and :func:`load_inlined` executes each block in its own fresh module
object, after re-checking its hash: the code that runs is byte for byte the
code that was hashed, and nothing leaks between oracles. (That re-check covers
the inlined BLOCKS only; the runtime and the plugin template around them, which
run as plain code, are covered by ``verify_inlined`` over the whole file and by
the blocks' hashes matching the repository.) Primitives that an
oracle lists in ``REQUIRES_PRIMITIVES`` are loaded the same way and bound as
globals of the oracle module under their own names.
"""
import hashlib
import linecache
import re
import sys
import types
from typing import NamedTuple

_INLINE_MARKER_PREFIX = "# --- memdiver "
_INLINE_MARKER = re.compile(
    r"# --- memdiver ([a-z]+):(\S+) sha256=([0-9a-f]{64}) (begin|end) ---\n?\Z"
)


class InlinedBlock(NamedTuple):
    """One inlined block. ``kind`` is the oracle KIND, or "<role>:<name>" otherwise."""

    kind: str
    sha256: str
    text: str


def inline_sha256(text):
    """SHA-256 (hex) of a block's text, as recorded in its markers."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def inline_marker(role, name, sha256, edge):
    """One marker line (with its newline); ``edge`` is "begin" or "end"."""
    return f"{_INLINE_MARKER_PREFIX}{role}:{name} sha256={sha256} {edge} ---\n"


def _inline_lines(source):
    """Split on "\\n" only, keeping it, so joining the lines restores ``source``."""
    lines = source.split("\n")
    return [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def _inline_scan(source):
    """Return ``(blocks, malformed)``: blocks as (role, name, sha256, text) tuples.

    ``malformed`` counts marker-like lines that do not form a proper
    begin/end pair (unknown shape, nesting, mismatched or missing end).
    """
    blocks, malformed, open_block, body = [], 0, None, []
    for line in _inline_lines(source):
        if not line.startswith(_INLINE_MARKER_PREFIX):
            if open_block is not None:
                body.append(line)
            continue
        match = _INLINE_MARKER.match(line)
        if match is None:
            malformed += 1
        elif match.group(4) == "begin":
            malformed += open_block is not None
            open_block, body = match.groups()[:3], []
        elif open_block == match.groups()[:3]:
            blocks.append(open_block + ("".join(body),))
            open_block = None
        else:
            malformed += 1
    return blocks, malformed + (open_block is not None)


def extract_inlined(source):
    """Every inlined block in ``source``, in order, as :class:`InlinedBlock`."""
    blocks, _ = _inline_scan(source)
    return [InlinedBlock(name if role == "oracle" else f"{role}:{name}", sha, text)
            for role, name, sha, text in blocks]


def verify_inlined(source):
    """True iff ``source`` holds at least one block, no stray markers, and every hash matches."""
    blocks, malformed = _inline_scan(source)
    return bool(blocks) and not malformed and all(
        inline_sha256(text) == sha for _, _, sha, text in blocks
    )


def _inline_index(source):
    blocks, malformed = _inline_scan(source)
    if malformed:
        raise ValueError(f"{malformed} malformed inline marker line(s); refusing to load")
    index = {}
    for role, name, sha, text in blocks:
        if index.get((role, name), (sha, text)) != (sha, text):
            raise ValueError(f"two different inlined blocks named {role}:{name}")
        index[(role, name)] = (sha, text)
    return index


def _inline_exec(index, role, name, bundle_sha):
    """Execute one integrity-checked block in its own module (cached in sys.modules).

    The cache key includes the SHA-256 of the whole inlined-sources string, so
    two plugins in one process never share (or rebind) each other's modules.
    """
    if (role, name) not in index:
        raise KeyError(f"no inlined {role}:{name}; available: {sorted(index)}")
    sha, text = index[(role, name)]
    if inline_sha256(text) != sha:
        raise ValueError(f"inlined {role}:{name} fails its sha256 check; refusing to execute it")
    module_name = "_memdiver_inlined_{}_{}_{}_{}".format(
        bundle_sha, role, re.sub(r"\W", "_", name), sha[:12])
    if module_name in sys.modules:
        return sys.modules[module_name]
    filename = f"<memdiver inlined {role}:{name}>"
    linecache.cache[filename] = (len(text), None, text.splitlines(True), filename)
    module = types.ModuleType(module_name)
    sys.modules[module_name] = module  # registered first, like a real import
    try:
        # Executing inlined source is the point; it was just checked against its sha256.
        exec(compile(text, filename, "exec"), module.__dict__)  # nosec B102
    except BaseException:
        del sys.modules[module_name]
        raise
    return module


def load_inlined(kind, source):
    """Load the inlined oracle ``kind`` from ``source`` (a plugin's inlined-sources string).

    Returns a module object exposing the format contract (``build_oracle``,
    ``KIND``, ...). Each primitive in its ``REQUIRES_PRIMITIVES`` that is
    inlined in ``source`` is loaded into its own module and bound as a global
    of the oracle module; a primitive that is absent is simply left unbound.
    """
    index = _inline_index(source)
    bundle_sha = inline_sha256(source)
    module = _inline_exec(index, "oracle", kind, bundle_sha)
    for name in getattr(module, "REQUIRES_PRIMITIVES", ()):
        if ("primitive", name) in index:
            setattr(module, name, _inline_exec(index, "primitive", name, bundle_sha))
    return module
