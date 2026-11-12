#!/usr/bin/env python3
"""Paramiko SSH client that logs its session's key ground truth (runs IN the guest).

    gt_ssh_client.py <host> <port> <user> <ed25519_key> <events.jsonl> <group> <conn_id>

One sibling-group connection (capture v2b): connects to an OpenSSH or dropbear
server, authenticates with the key, opens no channel (like ``ssh -N``) and then
stays connected and idle, so the server-side session processes hold live keys at
dump time. K, H, session_id and the derived keys A-F are logged by the same
``Transport._compute_key`` hook the SSH Tier A paramiko peer uses
(ssh_tier_a/gt_server.py); both ends of one SSH session derive identical keys,
so the client-side values are the server session's keys. A ``connected`` event
adds the client pid, its local port (which identifies the server-side socket)
and the negotiated algorithms. Prints ``READY ...`` once authenticated.
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ssh_tier_a"))

import gt_server  # noqa: E402  (reused hooks: _compute_key / _log_agreement / _log)
import paramiko  # noqa: E402


def main(argv):
    if len(argv) != 8:
        sys.exit(__doc__)
    host, port, user, key_path, events, group, conn_id = argv[1:]
    gt_server.GT_PATH = events
    gt_server.install_hooks()
    sock = socket.create_connection((host, int(port)))
    t = paramiko.Transport(sock)
    opts = t.get_security_options()
    opts.kex = [k for k in ("curve25519-sha256@libssh.org", "curve25519-sha256")
                if k in getattr(paramiko.Transport, "_kex_info", {k: 1})]
    opts.ciphers = ("aes256-ctr",)
    opts.digests = ("hmac-sha2-256",)
    t.start_client(timeout=60)
    t.auth_publickey(user, paramiko.Ed25519Key.from_private_key_file(key_path))
    if not t.is_authenticated():
        sys.exit("authentication failed")
    gt_server.log({
        "event": "connected", "t": time.time(), "group": group, "conn_id": conn_id,
        "client_pid": os.getpid(), "client_port": sock.getsockname()[1], "server_port": int(port),
        "cipher_c2s": t.local_cipher, "cipher_s2c": t.remote_cipher,
        "mac_c2s": t.local_mac, "mac_s2c": t.remote_mac,
        "remote_version": t.remote_version, "paramiko_version": paramiko.__version__,
    })
    print(f"READY pid={os.getpid()} conn_id={conn_id} client_port={sock.getsockname()[1]} "
          f"server={t.remote_version}", flush=True)
    while t.is_active():
        time.sleep(5)
    print("DISCONNECTED", flush=True)


if __name__ == "__main__":
    main(sys.argv)
