"""Capture target + device selection shared by every dump backend.

A capture names *what* to dump (a pid or a process name) and *where* it runs
(the local host, a USB-attached device such as an Android phone/emulator, or a
remote frida-server/gdbserver/lldb-server). Each backend translates the pair
into its own command-line flags; a combination the backend cannot express is
rejected with :class:`UnsupportedCaptureTarget` instead of silently dumping the
wrong process.

Device spec strings (the CLI device option, REST/MCP ``device``):

* ``local`` (default) -- the host MemDiver runs on.
* ``usb`` -- the first USB device Frida sees (memslicer ``-U``).
* ``usb:<device-id>`` -- a specific device by Frida id, e.g. ``usb:emulator-5554``
  (memslicer ``-D <id>``; use it when several devices are attached).
* ``remote:<host>[:<port>]`` -- a remote server (memslicer ``-R host:port``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

DEVICE_LOCAL = "local"
DEVICE_USB = "usb"
DEVICE_REMOTE = "remote"
DEVICE_KINDS = (DEVICE_LOCAL, DEVICE_USB, DEVICE_REMOTE)


class UnsupportedCaptureTarget(ValueError):
    """The backend cannot capture this target/device combination."""


@dataclass(frozen=True)
class CaptureDevice:
    """Where the target process runs."""

    kind: str = DEVICE_LOCAL
    device_id: Optional[str] = None     # usb only: Frida device id
    remote_addr: Optional[str] = None   # remote only: host[:port]

    @property
    def is_local(self) -> bool:
        return self.kind == DEVICE_LOCAL

    def to_spec(self) -> str:
        """Inverse of :func:`parse_device_spec`."""
        if self.kind == DEVICE_USB and self.device_id:
            return f"usb:{self.device_id}"
        if self.kind == DEVICE_REMOTE:
            return f"remote:{self.remote_addr}"
        return self.kind


def parse_device_spec(spec: Optional[str]) -> CaptureDevice:
    """Parse a device spec string (see module docstring); ``None``/``""`` is local."""
    text = (spec or DEVICE_LOCAL).strip()
    kind, _, rest = text.partition(":")
    kind = kind.lower()
    if kind == DEVICE_LOCAL and not rest:
        return CaptureDevice()
    if kind == DEVICE_USB:
        return CaptureDevice(DEVICE_USB, device_id=rest or None)
    if kind == DEVICE_REMOTE and rest:
        _validate_remote(rest)
        return CaptureDevice(DEVICE_REMOTE, remote_addr=rest)
    raise ValueError(
        f"invalid device {spec!r}: expected local, usb, usb:<device-id> "
        "or remote:<host>[:<port>]")


def _validate_remote(addr: str) -> None:
    host, sep, port = addr.rpartition(":")
    if not sep:
        return
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"invalid remote address {addr!r}: expected host[:port]")


@dataclass(frozen=True)
class CaptureTarget:
    """The process to dump: by pid or by process name, on a device."""

    pid: Optional[int] = None
    name: Optional[str] = None
    device: CaptureDevice = CaptureDevice()

    def __post_init__(self):
        if (self.pid is None) == (not self.name):
            raise ValueError("capture target needs exactly one of pid or name")
        if self.pid is not None and self.pid <= 0:
            raise ValueError(f"invalid pid {self.pid}")

    @property
    def label(self) -> str:
        """The pid as text, else the process name (backend positional arg)."""
        return str(self.pid) if self.pid is not None else str(self.name)

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name, "device": self.device.to_spec()}


def parse_target(pid_or_name: "str | int", device: Optional[str] = None) -> CaptureTarget:
    """Build a target from ``"1234"``/``1234`` (pid) or ``"com.app"`` (name)."""
    dev = parse_device_spec(device)
    if isinstance(pid_or_name, int):
        return CaptureTarget(pid=pid_or_name, device=dev)
    text = str(pid_or_name).strip()
    if text.isdigit():
        return CaptureTarget(pid=int(text), device=dev)
    return CaptureTarget(name=text, device=dev)


def memslicer_device_args(device: CaptureDevice) -> List[str]:
    """memslicer ``acquire`` transport flags (``-U`` / ``-D`` / ``-R``)."""
    if device.kind == DEVICE_USB:
        return ["-D", device.device_id] if device.device_id else ["-U"]
    if device.kind == DEVICE_REMOTE:
        return ["-R", device.remote_addr]
    return []


def memslicer_acquire_args(target: "CaptureTarget", output: str,
                           max_region_size: Optional[int] = None) -> List[str]:
    """Full memslicer argv: ``memslicer acquire <pid|name> -o <out> [transport]``.

    memslicer's own option names are third-party command lines (the reason
    this module is exempt from the no-CLI-flags-in-core invariant).
    """
    argv = ["memslicer", "acquire", target.label, "-o", str(output),
            *memslicer_device_args(target.device)]
    if max_region_size:
        argv += ["--max-region-size", str(max_region_size)]
    return argv


def fridump_device_args(device: CaptureDevice) -> List[str]:
    """fridump transport flags; fridump only knows local and ``-U``."""
    if device.kind == DEVICE_USB and not device.device_id:
        return ["-U"]
    if device.is_local:
        return []
    raise UnsupportedCaptureTarget(
        f"fridump cannot capture on device {device.to_spec()!r} (it supports "
        "local and the first USB device only); use the memslicer backend")


def require_local(device: CaptureDevice, backend: str) -> None:
    """Reject non-local devices for host-only backends (lldb)."""
    if not device.is_local:
        raise UnsupportedCaptureTarget(
            f"{backend} captures local processes only (device "
            f"{device.to_spec()!r}); use the memslicer backend for devices")
