#!/usr/bin/env python3
"""Verify ASLR is active on the current platform.

Performs three checks:
1. PIE flag on the Python interpreter binary (macOS: otool, Linux: readelf)
2. Spawn two short-lived Python processes and compare heap base addresses
3. Report summary: ASLR ACTIVE / ASLR DISABLED / ASLR UNKNOWN

Usage: python verify_aslr.py
"""

import ctypes
import platform
import subprocess
import sys
import textwrap
from pathlib import Path


def check_pie_flag() -> dict:
    """Check if the Python binary has the PIE (Position Independent Executable) flag."""
    python_path = sys.executable
    system = platform.system()
    result = {"check": "PIE flag", "binary": python_path, "status": "unknown"}

    if system == "Darwin":
        try:
            out = subprocess.check_output(
                ["otool", "-hv", python_path],
                stderr=subprocess.STDOUT, text=True, timeout=10,
            )
            result["raw_output"] = out.strip()
            if "PIE" in out:
                result["status"] = "PASS"
                result["detail"] = "PIE flag present — binary supports ASLR"
            else:
                result["status"] = "WARN"
                result["detail"] = "PIE flag NOT found — ASLR may be limited"
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            result["status"] = "error"
            result["detail"] = str(e)

    elif system == "Linux":
        try:
            out = subprocess.check_output(
                ["readelf", "-h", python_path],
                stderr=subprocess.STDOUT, text=True, timeout=10,
            )
            result["raw_output"] = out.strip()
            if "DYN" in out:
                result["status"] = "PASS"
                result["detail"] = "ELF type is DYN (PIE) — binary supports ASLR"
            elif "EXEC" in out:
                result["status"] = "WARN"
                result["detail"] = "ELF type is EXEC (non-PIE) — ASLR limited"
            else:
                result["status"] = "unknown"
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            result["status"] = "error"
            result["detail"] = str(e)
    else:
        result["detail"] = f"Unsupported platform: {system}"

    return result


def _get_heap_address() -> str | None:
    """Spawn a Python subprocess that prints its heap base address."""
    script = textwrap.dedent("""\
        import ctypes, sys
        buf = ctypes.create_string_buffer(256)
        print(f"0x{ctypes.addressof(buf):016x}")
    """)
    try:
        out = subprocess.check_output(
            [sys.executable, "-c", script],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        return out.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def check_address_randomization() -> dict:
    """Spawn two processes and compare heap buffer addresses."""
    result = {"check": "address randomization", "status": "unknown"}

    addr1 = _get_heap_address()
    addr2 = _get_heap_address()

    if addr1 is None or addr2 is None:
        result["status"] = "error"
        result["detail"] = "Failed to get heap addresses from subprocesses"
        return result

    result["address_1"] = addr1
    result["address_2"] = addr2

    if addr1 != addr2:
        result["status"] = "PASS"
        result["detail"] = (
            f"Heap addresses differ: {addr1} vs {addr2} — ASLR active"
        )
    else:
        result["status"] = "FAIL"
        result["detail"] = (
            f"Heap addresses identical: {addr1} — ASLR may be disabled"
        )

    return result


def check_system_aslr_setting() -> dict:
    """Check OS-level ASLR configuration."""
    system = platform.system()
    result = {"check": "system ASLR setting", "status": "unknown"}

    if system == "Darwin":
        # macOS has ASLR enabled by default since 10.7, no sysctl to check
        result["status"] = "PASS"
        result["detail"] = "macOS enables ASLR by default (since 10.7 Lion)"

    elif system == "Linux":
        aslr_path = Path("/proc/sys/kernel/randomize_va_space")
        if aslr_path.exists():
            val = aslr_path.read_text().strip()
            result["value"] = val
            if val == "2":
                result["status"] = "PASS"
                result["detail"] = "randomize_va_space=2 (full ASLR)"
            elif val == "1":
                result["status"] = "WARN"
                result["detail"] = "randomize_va_space=1 (partial ASLR)"
            elif val == "0":
                result["status"] = "FAIL"
                result["detail"] = "randomize_va_space=0 (ASLR disabled!)"
        else:
            result["detail"] = "/proc/sys/kernel/randomize_va_space not found"
    else:
        result["detail"] = f"Unsupported platform: {system}"

    return result


def verify_aslr() -> dict:
    """Run all ASLR checks and return summary."""
    checks = [
        check_pie_flag(),
        check_address_randomization(),
        check_system_aslr_setting(),
    ]

    passes = sum(1 for c in checks if c["status"] == "PASS")
    fails = sum(1 for c in checks if c["status"] == "FAIL")

    if fails > 0:
        overall = "ASLR DISABLED"
    elif passes >= 2:
        overall = "ASLR ACTIVE"
    else:
        overall = "ASLR UNKNOWN"

    return {"overall": overall, "checks": checks}


def main():
    """Run verification and print results."""
    result = verify_aslr()

    print(f"\n{'=' * 60}")
    print(f"  ASLR Verification: {result['overall']}")
    print(f"{'=' * 60}")

    for check in result["checks"]:
        status = check["status"]
        icon = {"PASS": "[OK]", "FAIL": "[!!]", "WARN": "[??]"}.get(status, "[--]")
        print(f"\n  {icon} {check['check']}")
        if "detail" in check:
            print(f"      {check['detail']}")
        if "address_1" in check:
            print(f"      Process 1: {check['address_1']}")
            print(f"      Process 2: {check['address_2']}")

    print(f"\n{'=' * 60}\n")
    return 0 if result["overall"] == "ASLR ACTIVE" else 1


if __name__ == "__main__":
    sys.exit(main())
