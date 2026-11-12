#!/usr/bin/env python3
"""Paramiko SSH server that logs session-key ground truth (runs IN the guest).

    gt_server.py <port> <events.jsonl>

Wraps ``Transport._compute_key`` so every derived key (A..F) is appended to the
events file together with K (shared secret), H (exchange hash), session_id and
the negotiated algorithms. Values come from paramiko itself (the wrapped call's
return value and the transport's attributes); nothing is recomputed here. The
client is the process under test; this server is only its ground-truth peer.
Accepts user ``testuser`` / password ``password``; exec requests are echoed.
Every hook is installed only if the paramiko version has the hooked method.
"""
import json
import os
import socket
import sys
import threading
import time

import paramiko
from paramiko.message import Message

LOCK = threading.Lock()
GT_PATH = ""


def log(rec):
    with LOCK, open(GT_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def mpint_bytes(k_int):
    msg = Message()
    msg.add_mpint(k_int)   # paramiko's own mpint encoding
    return msg.asbytes()


def _agreed(transport):
    return transport.__dict__.setdefault("_gt_agreed", {})


def _hook_compute_key(orig):
    def hooked(self, id, nbytes):
        out = orig(self, id, nbytes)
        kex = getattr(self, "kex_engine", None)
        hash_algo = getattr(kex, "hash_algo", None) if kex else None
        log({
            "event": "compute_key", "t": time.time(), "server_pid": os.getpid(),
            "letter": id.decode() if isinstance(id, bytes) else str(id),
            "nbytes": nbytes, "key_hex": out.hex(),
            "K_int_hex": format(self.K, "x"), "K_mpint_hex": mpint_bytes(self.K).hex(),
            "H_hex": self.H.hex(), "session_id_hex": self.session_id.hex(),
            "kex_engine": kex.__class__.__name__ if kex else None,
            "agreed": dict(_agreed(self)),
            "hash": getattr(hash_algo, "__name__", str(hash_algo)).replace("openssl_", ""),
            "remote_version": self.remote_version, "local_version": self.local_version,
        })
        return out
    return hooked


def _hook_log_agreement(orig):
    def hooked(self, which, local, remote):
        _agreed(self)[which] = {"local": local, "remote": remote}
        return orig(self, which, local, remote)
    return hooked


def _hook_log(orig):
    def hooked(self, level, msg, *args):
        if isinstance(msg, str) and msg.startswith("Kex: "):   # older paramiko: only a log line
            _agreed(self).setdefault("Kex", {"local": msg[5:], "remote": msg[5:]})
        return orig(self, level, msg, *args)
    return hooked


def install_hooks():
    T = paramiko.Transport
    T._compute_key = _hook_compute_key(T._compute_key)
    if hasattr(T, "_log_agreement"):
        T._log_agreement = _hook_log_agreement(T._log_agreement)
    T._log = _hook_log(T._log)
    kex_info = getattr(T, "_kex_info", {})
    if "curve25519-sha256@libssh.org" in kex_info:   # RFC 8731 alias
        kex_info.setdefault("curve25519-sha256", kex_info["curve25519-sha256@libssh.org"])


class Srv(paramiko.ServerInterface):
    def check_auth_password(self, user, password):
        ok = (user, password) == ("testuser", "password")
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, user):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        def run():
            time.sleep(0.3)   # let the exec-request success reply go out first
            channel.sendall(b"memdiver-gt-server exec: " + command + b"\n")
            channel.send_exit_status(0)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


def handle(sock, addr, host_key):
    t = paramiko.Transport(sock)
    opts = t.get_security_options()
    opts.kex = [k for k in ("curve25519-sha256@libssh.org", "curve25519-sha256")
                if k in getattr(paramiko.Transport, "_kex_info", {k: 1})]
    opts.ciphers = ("aes256-ctr", "aes128-ctr")
    opts.digests = ("hmac-sha2-256",)
    t.add_server_key(host_key)
    t.start_server(server=Srv())
    while t.is_active() and not t.is_authenticated():
        time.sleep(0.1)
    log({"event": "negotiated", "t": time.time(), "server_pid": os.getpid(), "peer": str(addr),
         "agreed": dict(_agreed(t)), "host_key_type": getattr(t, "host_key_type", None),
         "cipher_c2s": t.remote_cipher, "cipher_s2c": t.local_cipher,
         "mac_c2s": t.remote_mac, "mac_s2c": t.local_mac,
         "remote_version": t.remote_version, "paramiko_version": paramiko.__version__})
    while t.is_active():
        time.sleep(1)


def main(argv):
    global GT_PATH
    if len(argv) != 3:
        sys.exit(__doc__)
    port, GT_PATH = int(argv[1]), argv[2]
    install_hooks()
    host_key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    print(f"READY gt_server pid={os.getpid()} port={port} paramiko={paramiko.__version__}",
          flush=True)
    while True:
        sock, addr = listener.accept()
        threading.Thread(target=handle, args=(sock, addr, host_key), daemon=True).start()


if __name__ == "__main__":
    main(sys.argv)
