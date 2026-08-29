"""The packaging contract in one place: what ``pip install memdiver`` provides,
and what pip cannot provide at all.

Three distinct conditions reach a user as a "missing dependency" message, and
each needs a *different* action:

1. A genuinely-optional extra is absent. ``marimo`` and ``vol``
   (Volatility3, for running the emitted plugins) plus the tooling-only
   ``dev``/``docs`` groups are what is left in this class.
2. A BASE package is absent -- a force-uninstall or an otherwise broken
   environment. A ``memdiver[<extra>]`` hint is actively misleading here,
   because since 0.6 those extras are empty back-compat aliases that install
   nothing; the fix is a reinstall.
3. The Python package IS installed but a NATIVE runtime piece is not: the
   liboqs C library behind liboqs-python, an attachable target for frida, or
   LLDB, which ships with the operating system. No pip command can fix any of
   these, so the message must name the OS-level action instead.

Every user-facing install hint is built from this module so the contract moves
in one edit when ``pyproject.toml`` changes, instead of drifting across the
dozen call sites that report an absent dependency.
"""

from __future__ import annotations

#: Optional-dependency groups that still install something. Membership here is
#: what makes ``missing_package_message(..., extra=...)`` render the
#: ``pip install "memdiver[<extra>]"`` form instead of degrading to the
#: base-reinstall wording -- so a new opt-in extra must be added here, and must
#: NOT be added to :data:`NO_OP_EXTRAS`.
OPTIONAL_EXTRAS = frozenset({"marimo", "vol", "dev", "docs"})

#: Extra names kept only so already-published commands ("pip install
#: memdiver[api]") keep RESOLVING; their contents moved into the base install,
#: so they now add nothing. A call site naming one of these is really reporting
#: a broken environment (class 2), not a forgotten extra.
NO_OP_EXTRAS = frozenset({"api", "mcp", "pcap", "experiment", "crypto"})

#: The command that repairs a base install whose package went missing.
BASE_INSTALL_HINT = "pip install --force-reinstall memdiver"


def extra_install_hint(extra: str) -> str:
    """Return the shell command that installs *extra*.

    Quoted because zsh -- the macOS default shell -- globs bare square
    brackets and would fail the unquoted form with "no matches found".
    """
    return f'pip install "memdiver[{extra}]"'


def missing_package_message(package: str, extra: str | None = None) -> str:
    """Build the hint for an absent *Python* package (class 1 or class 2).

    ``extra`` names the optional-dependencies group the package used to come
    from. A group that no longer installs anything (:data:`NO_OP_EXTRAS`)
    degrades to the base-reinstall wording, so a call site can keep passing the
    name it always passed and still print the correct action.
    """
    if extra and extra not in NO_OP_EXTRAS:
        return (
            f"{package} is not available. Install the '{extra}' extra with:\n"
            f"    {extra_install_hint(extra)}"
        )
    return (
        f"{package} is missing from your environment. It is part of the base "
        f"install; restore it with:\n    {BASE_INSTALL_HINT}"
    )


#: The OS-level action for each native runtime piece, keyed by the name a call
#: site already knows. Deliberately free of pip commands: pip cannot install a
#: C library, an OS debugger, or a live process to attach to, so a pip hint
#: would send the user down a road that cannot end in a fix.
NATIVE_RUNTIMES: dict[str, str] = {
    "liboqs": (
        "the liboqs C library is not usable. liboqs-python ships bindings only "
        "and is already part of the base install; on first use it downloads "
        "and cmake-builds liboqs into ~/_oqs, so that machine needs cmake, "
        "git and a C compiler (`xcode-select --install` on macOS, "
        "`apt install cmake git build-essential` on Debian/Ubuntu). Prebuild "
        "it instead with `brew install liboqs` / `apt install liboqs-dev` and "
        "point OQS_INSTALL_PATH at the result. Only if the Python package "
        f"itself is gone is `{BASE_INSTALL_HINT}` the fix."
    ),
    "frida": (
        "frida-tools is already part of the base install, but attaching needs "
        "a live target this platform lets Frida instrument. Start the target "
        "process first; on macOS also run `DevToolsSecurity -enable` once and "
        "re-run as root, and on Linux allow ptrace "
        "(`sysctl kernel.yama.ptrace_scope=0`)."
    ),
    "lldb": (
        "LLDB comes from the operating system, not from pip: install the Xcode "
        "Command Line Tools with `xcode-select --install` (macOS), or run "
        "`apt install lldb` (Debian/Ubuntu)."
    ),
}

#: The remedy for "this machine can capture nothing", spelled out per tool
#: because the three backends fail for three different reasons: the pip halves
#: (frida-tools, memslicer) ship in the base install, LLDB is an OS package,
#: and Frida additionally needs a target it is allowed to instrument.
CAPTURE_BACKEND_HINT = (
    "no memory-capture tool is usable on this machine. frida-tools and "
    "memslicer are part of the base install — if they are gone, run "
    f"`{BASE_INSTALL_HINT}`. LLDB is an OS package: `xcode-select --install` "
    "(macOS) or `apt install lldb` (Debian/Ubuntu). Frida also needs a live "
    "target it is permitted to attach to."
)


def native_runtime_message(component: str, detail: str = "") -> str:
    """Build the hint for a present-but-unusable NATIVE runtime piece (class 3).

    *detail* is an optional leading sentence naming what the user was trying to
    do; the OS-level action from :data:`NATIVE_RUNTIMES` is appended so the
    message always ends in something the user can run.
    """
    action = NATIVE_RUNTIMES.get(
        component,
        f"{component} is a native runtime component and must be installed "
        f"through your operating system's package manager.",
    )
    return f"{detail}: {action}" if detail else action
