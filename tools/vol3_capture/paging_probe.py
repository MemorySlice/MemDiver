#!/usr/bin/env python3
"""Report the guest's page-table depth as JSON (runs IN the guest).

x86_64 5-level paging (LA57) is decided by three independent signals:
  cpuinfo_la57      the kernel clears the `la57` cpu flag unless it actually
                    enabled 5-level paging (CPU support alone is not enough);
  mmap_above_47bit  an mmap hint above 2^47 is honoured only with 5-level
                    paging (user VA grows from 47 to 56 bits);
  dmesg             boot-log lines mentioning 5-level paging, if any.
On non-x86 architectures only the mmap probe is meaningful.
"""

from __future__ import annotations

import ctypes
import json
import mmap
import platform
import subprocess

HINT = 1 << 50


def mmap_above_47bit() -> bool | None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    addr = libc.mmap(HINT, 4096, mmap.PROT_READ, flags, -1, 0)
    if addr in (None, ctypes.c_void_p(-1).value):
        return None
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap(addr, 4096)
    return addr >= (1 << 47)


def cpuinfo_flag(flag: str) -> bool:
    with open("/proc/cpuinfo", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("flags"):
                return flag in line.split(":", 1)[1].split()
    return False


def dmesg_lines() -> list[str]:
    try:
        out = subprocess.run(["dmesg"], capture_output=True, text=True, check=False).stdout
    except OSError:
        return []
    return [ln.strip() for ln in out.splitlines() if "5-level" in ln or "la57" in ln.lower()]


def main() -> None:
    high = mmap_above_47bit()
    la57 = cpuinfo_flag("la57") if platform.machine() == "x86_64" else None
    levels = 5 if (la57 or high) else 4
    print(json.dumps({
        "machine": platform.machine(), "cpuinfo_la57": la57,
        "mmap_above_47bit": high, "dmesg": dmesg_lines(),
        "page_table_levels": levels if platform.machine() == "x86_64" else None,
    }))


if __name__ == "__main__":
    main()
