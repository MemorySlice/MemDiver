#!/usr/bin/env python3
"""Ground-truth sidecar builder for secrets_stage.sh (runs IN the guest).

The stage script appends one JSON object per recorded fact to a fragments
file, then calls ``finalize`` once to fold them into ``secrets.json``
(schema ``memdiver-secrets-gt/1``, documented in README.md).

Subcommands
-----------
  add FRAGS SECTION k=v k:=<json> k@=<file> ...
        Append one record to SECTION. ``k=v`` stores a string, ``k:=`` parses
        JSON, ``k@=`` stores the stripped text content of a file.
  key FRAGS ID KIND HEX SOURCE [note]
        Append one raw secret to the flat ``keys[]`` list.
  kernel FRAGS KEY JSON
        Merge KEY into the top-level ``kernel{}`` object (e.g. paging).
  gap FRAGS ITEM REASON
        Record a capability gap (an item that could not be planted).
  wg FRAGS NETNS DUMP_TXT [EXTRA_JSON]
        Parse ``wg show all dump`` into ``wireguard[]`` records.
  btf FRAGS SOURCE PAHOLE_TXT
        Parse ``pahole -C`` output into ``btf_offsets{}``.
  ssh-tier-a FRAGS EVENTS_JSONL CLIENT_LOG CLIENT_PID [SERVER_PID]
        Fold the paramiko ground-truth server's events (K, H, session_id,
        derived keys A-F, negotiated algorithms) and the libssh client's log
        into one ``ssh_tier_a[]`` record, plus ``keys[]`` entries.
  sibling-plan SIBDIR PLAN_JSON
        Assemble the sibling-group plan (capture v2b) from SIBDIR: ``group_*.json``
        (group, expected_shape, listener_pid, server_port), ``events_*.jsonl``
        (one per SSH connection, from siblings/gt_ssh_client.py) and
        ``mount_*.json`` (one per gocryptfs mount). Each connection gets its
        ground truth (``gt``) and the ``secrets`` the frame scan looks for.
  siblings FRAGS PLAN_JSON COLLECTED_JSON
        Fold sibling_frames.py's collected members + the plan's per-connection
        ground truth into ``siblings[]`` (one record per member), plus
        ``keys[]`` entries per connection.
  ecryptfs-fekek PASSPHRASE
        Print ``<fekek_hex> <signature>`` for an eCryptfs passphrase
        (ecryptfs-utils default salt, 65536 SHA-512 rounds).
  finalize FRAGS OUT ARCH
        Write secrets.json.

Python 3 standard library only, so it runs on any stock cloud image.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone

SCHEMA = "memdiver-secrets-gt/1"
LIST_SECTIONS = (
    "dmcrypt", "wireguard", "keys", "fscrypt", "ecryptfs", "gocryptfs", "ssh", "ssh_tier_a",
    "gaps",
)
SSH_KEY_LETTERS = "ABCDEF"
SSH_KEY_ROLES = {"A": "iv_c2s", "B": "iv_s2c", "C": "enc_c2s", "D": "enc_s2c",
                 "E": "mac_c2s", "F": "mac_s2c"}
ECRYPTFS_DEFAULT_SALT = bytes.fromhex("0011223344556677")
ECRYPTFS_HASH_ROUNDS = 65536
PAHOLE_MEMBER = re.compile(
    r"^\s+(?P<decl>.+?);\s*/\*\s*(?P<off>\d+)(?::\s*\d+)?\s+(?P<size>\d+)\s*\*/"
)
PAHOLE_SIZE = re.compile(r"/\*\s*size:\s*(\d+)")


def _append(frags: str, section: str, record: object) -> None:
    with open(frags, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"section": section, "record": record}) + "\n")


def _parse_pairs(pairs: list[str]) -> dict:
    record: dict = {}
    for pair in pairs:
        key, value = pair.split("=", 1)
        if key.endswith(":"):
            record[key[:-1]] = json.loads(value)
        elif key.endswith("@"):
            with open(value, encoding="utf-8", errors="replace") as fh:
                record[key[:-1]] = fh.read().strip()
        else:
            record[key] = value
    return record


def cmd_add(frags: str, section: str, *pairs: str) -> None:
    _append(frags, section, _parse_pairs(list(pairs)))


def cmd_key(frags: str, key_id: str, kind: str, hexval: str, source: str, note: str = "") -> None:
    raw = bytes.fromhex(hexval)
    _append(frags, "keys", {
        "id": key_id, "kind": kind, "hex": raw.hex(), "length": len(raw),
        "source": source, "note": note,
    })


def cmd_kernel(frags: str, key: str, value_json: str) -> None:
    _append(frags, "kernel_extra", {key: json.loads(value_json)})


def cmd_gap(frags: str, item: str, reason: str) -> None:
    _append(frags, "gaps", {"item": item, "reason": reason})


def _member_name(decl: str) -> str:
    decl = re.sub(r"__attribute__\s*\(\(.*\)\)", "", decl)   # drop alignment attrs
    decl = decl.split(":")[0].strip()          # drop bitfield width
    if "(" in decl:                             # function pointer: (*name)(...)
        match = re.search(r"\(\s*\*\s*(\w+)\s*\)", decl)
        return match.group(1) if match else decl
    decl = re.sub(r"\[.*?\]", "", decl)        # drop array extents
    return decl.replace("*", " ").split()[-1]


def parse_pahole(text: str) -> dict:
    """Top-level struct layout from ``pahole -C`` text: {struct: {size, members}}."""
    out: dict = {}
    current = None
    depth = 0
    for line in text.splitlines():
        if depth == 0:
            match = re.match(r"^struct (\w+) \{", line)
            if match:
                current = match.group(1)
                out[current] = {"size": None, "members": {}}
                depth = 1
            continue
        depth += line.count("{") - line.count("}")
        if depth == 0:
            size = PAHOLE_SIZE.search(line)
            if current and size:
                out[current]["size"] = int(size.group(1))
            current = None
            continue
        if depth == 1 and current:
            match = PAHOLE_MEMBER.match(line)
            if match:
                name = _member_name(match.group("decl"))
                out[current]["members"].setdefault(name, {
                    "offset": int(match.group("off")), "size": int(match.group("size")),
                    "decl": match.group("decl").strip(),
                })
        if depth == 1 and current and "size:" in line:
            size = PAHOLE_SIZE.search(line)
            if size:
                out[current]["size"] = int(size.group(1))
    return out


def cmd_btf(frags: str, source: str, path: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as fh:
        parsed = parse_pahole(fh.read())
    for name, layout in parsed.items():
        layout["source"] = source
        _append(frags, "btf_offsets", {name: layout})


def _b64_hex(value: str) -> str | None:
    if value in ("", "(none)", "off"):
        return None
    return base64.b64decode(value).hex()


def parse_wg_dump(text: str, netns: str, extra: dict) -> list[dict]:
    """``wg show all dump`` -> one record per interface with its peers."""
    interfaces: dict = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 5:
            iface, priv, pub, port, fwmark = fields
            interfaces[iface] = {
                "netns": netns, "interface": iface,
                "private_key_b64": priv, "private_key_hex": _b64_hex(priv),
                "public_key_b64": pub, "listen_port": int(port), "fwmark": fwmark,
                "peers": [], **extra,
            }
        elif len(fields) == 9 and fields[0] in interfaces:
            iface, pub, psk, endpoint, allowed, latest, rx, tx, keepalive = fields
            interfaces[iface]["peers"].append({
                "public_key_b64": pub, "preshared_key_b64": None if psk == "(none)" else psk,
                "preshared_key_hex": _b64_hex(psk), "endpoint": endpoint,
                "allowed_ips": allowed, "latest_handshake_unix": int(latest),
                "rx_bytes": int(rx), "tx_bytes": int(tx), "persistent_keepalive": keepalive,
            })
    return list(interfaces.values())


def cmd_wg(frags: str, netns: str, dump_path: str, extra_json: str = "{}") -> None:
    with open(dump_path, encoding="utf-8") as fh:
        for record in parse_wg_dump(fh.read(), netns, json.loads(extra_json)):
            _append(frags, "wireguard", record)


def _client_log_fields(text: str) -> dict:
    """``negotiated kex=.. cipher_out=..`` and ``READY pid=.. libssh=..`` lines."""
    out: dict = {}
    for line in text.splitlines():
        if line.startswith(("negotiated ", "READY ")):
            for token in line.split()[1:]:
                if "=" in token:
                    key, value = token.split("=", 1)
                    out[key] = value
    return out


def ssh_tier_a_record(events: list[dict], client_log: str, client_pid: int,
                      server_pid: int | None = None) -> dict:
    """One Tier A record from the peer-side ground-truth events (latest key exchange)."""
    derived = [e for e in events if e.get("event") == "compute_key"]
    if not derived:
        raise ValueError("no compute_key events: the client never completed a key exchange")
    latest_h = derived[-1]["H_hex"]
    kex_keys = [e for e in derived if e["H_hex"] == latest_h]
    last = kex_keys[-1]
    negotiated = [e for e in events if e.get("event") == "negotiated"]
    neg = negotiated[-1] if negotiated else {}
    client = _client_log_fields(client_log)
    kex_name = (last.get("agreed", {}).get("Kex", {}) or {}).get("local") or client.get("kex")
    return {
        "implementation": "libssh", "version": client.get("libssh"), "role": "client",
        "pid": client_pid, "pid_from_client_log": int(client["pid"]) if "pid" in client else None,
        "server_implementation": "paramiko", "server_pid": server_pid or last.get("server_pid"),
        "server_version": neg.get("paramiko_version"),
        "kex": kex_name, "hash": last.get("hash"),
        "cipher_c2s": neg.get("cipher_c2s") or client.get("cipher_out"),
        "cipher_s2c": neg.get("cipher_s2c") or client.get("cipher_in"),
        "mac_c2s": neg.get("mac_c2s") or client.get("hmac_out"), "mac_s2c": neg.get("mac_s2c"),
        "K_hex": last["K_mpint_hex"], "K_int_hex": last["K_int_hex"],
        "H_hex": last["H_hex"], "session_id_hex": last["session_id_hex"],
        "rekeyed": len({e["H_hex"] for e in derived}) > 1,
        "keys": {e["letter"]: e["key_hex"]
                 for e in sorted(kex_keys, key=lambda e: e["letter"])
                 if e["letter"] in SSH_KEY_LETTERS},
        "K_encoding": "RFC 4251 mpint (uint32 length || two's-complement big-endian), as hashed "
                      "into H and the RFC 4253 7.2 KDF; K_int_hex is the bare value",
        "keys_note": "RFC 4253 7.2 letters: A/B IV c2s/s2c, C/D enc key c2s/s2c, "
                     "E/F MAC key c2s/s2c",
        "gt_source": "paramiko server Transport._compute_key hook (peer of the client, "
                     "same session)",
    }


def _even_hex(value: str, min_len: int) -> str:
    """Left-pad a bare hex integer to an even length of at least MIN_LEN digits."""
    width = max(min_len, len(value) + len(value) % 2)
    return value.rjust(width, "0")


def cmd_ssh_tier_a(frags: str, events_path: str, client_log_path: str, client_pid: str,
                   server_pid: str = "") -> None:
    with open(events_path, encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh if line.strip()]
    with open(client_log_path, encoding="utf-8", errors="replace") as fh:
        client_log = fh.read()
    record = ssh_tier_a_record(events, client_log, int(client_pid),
                               int(server_pid) if server_pid else None)
    _append(frags, "ssh_tier_a", record)
    source = f"ssh-tier-a:libssh-client:{record['pid']}"
    cmd_key(frags, "ssh_tier_a.K", "ssh-shared-secret-int", _even_hex(record["K_int_hex"], 64),
            source, "bare big-endian K (curve25519: 32 bytes)")
    cmd_key(frags, "ssh_tier_a.session_id", "ssh-session-id", record["session_id_hex"], source)
    for letter, hexval in sorted(record["keys"].items()):
        cmd_key(frags, f"ssh_tier_a.{letter}", f"ssh-{SSH_KEY_ROLES[letter]}", hexval, source)


# --- sibling groups (capture v2b) ---------------------------------------------------------

SIBLING_SSH_SECRETS = {"K": None, "iv_c2s": "A", "iv_s2c": "B", "enc_c2s": "C",
                       "enc_s2c": "D", "mac_c2s": "E", "mac_s2c": "F"}


def ssh_session_gt(events: list[dict]) -> dict:
    """Session ground truth of one SSH connection from its client's hook events."""
    derived = [e for e in events if e.get("event") == "compute_key"]
    if not derived:
        raise ValueError("no compute_key events: the connection never completed a key exchange")
    latest_h = derived[-1]["H_hex"]
    last = [e for e in derived if e["H_hex"] == latest_h]
    keys = {e["letter"]: e["key_hex"] for e in last if e["letter"] in SSH_KEY_LETTERS}
    conn = next((e for e in reversed(events) if e.get("event") == "connected"), {})
    kex = (last[-1].get("agreed", {}).get("Kex", {}) or {}).get("local")
    session_keys = {
        direction: {
            "cipher": conn.get(f"cipher_{direction}"), "mac": conn.get(f"mac_{direction}"),
            "iv_hex": keys.get(iv), "enc_key_hex": keys.get(enc), "mac_key_hex": keys.get(mac),
        }
        for direction, (iv, enc, mac) in (("c2s", "ACE"), ("s2c", "BDF"))
    }
    return {
        "client_pid": conn.get("client_pid"), "client_port": conn.get("client_port"),
        "server_port": conn.get("server_port"), "server_version": conn.get("remote_version"),
        "client_implementation": f"paramiko {conn.get('paramiko_version')}",
        "kex": kex, "hash": last[-1].get("hash"),
        "cipher_c2s": conn.get("cipher_c2s"), "cipher_s2c": conn.get("cipher_s2c"),
        "mac_c2s": conn.get("mac_c2s"), "mac_s2c": conn.get("mac_s2c"),
        "K_hex": last[-1]["K_mpint_hex"], "K_int_hex": last[-1]["K_int_hex"],
        "H_hex": latest_h, "session_id_hex": last[-1]["session_id_hex"],
        "rekeyed": len({e["H_hex"] for e in derived}) > 1,
        "keys": dict(sorted(keys.items())), "session_keys": session_keys,
        "gt_source": "paramiko client Transport._compute_key hook (same session as the "
                     "server-side member)",
    }


def ssh_frame_secrets(gt: dict) -> dict:
    """The byte strings the frame scan searches in an SSH member: bare K + keys A-F."""
    out = {}
    for name, letter in SIBLING_SSH_SECRETS.items():
        value = _even_hex(gt["K_int_hex"], 64) if letter is None else gt["keys"].get(letter)
        if value:
            out[name] = value
    return out


def _read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def sibling_plan(sibdir: str) -> dict:
    """Plan dict ``{"groups": [...]}`` from the files the stage wrote into SIBDIR."""
    groups: dict = {}
    names = sorted(os.listdir(sibdir))
    for name in names:
        if name.startswith("group_") and name.endswith(".json"):
            group = _read_json(os.path.join(sibdir, name))
            groups[group["group"]] = {**group, "connections": []}
    for name in names:
        path = os.path.join(sibdir, name)
        if name.startswith("events_") and name.endswith(".jsonl"):
            events = _read_jsonl(path)
            conn = [e for e in events if e.get("event") == "connected"][-1]
            gt = ssh_session_gt(events)
            groups[conn["group"]]["connections"].append({
                "conn_id": conn["conn_id"], "client_pid": conn["client_pid"],
                "client_port": conn["client_port"], "gt": gt, "secrets": ssh_frame_secrets(gt),
            })
        elif name.startswith("mount_") and name.endswith(".json"):
            mount = _read_json(path)
            group = groups[mount["group"]]
            group["connections"].append({"conn_id": mount["conn_id"], "gt": mount,
                                         "secrets": {"master_key": mount["master_key_hex"]}})
            group.setdefault("members", []).append(
                {"pid": mount["daemon_pid"], "role": "daemon", "conn_id": mount["conn_id"]})
    for group in groups.values():
        group["connections"].sort(key=lambda c: c["conn_id"])
        pids = [m["pid"] for m in group.get("members", [])]
        for conn in group["connections"]:
            if "daemon_pid" in conn["gt"]:
                conn["gt"]["own_process"] = pids.count(conn["gt"]["daemon_pid"]) == 1
    return {"groups": list(groups.values())}


def cmd_sibling_plan(sibdir: str, plan_path: str) -> None:
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(sibling_plan(sibdir), fh, indent=2)


def sibling_records(plan: dict, collected: dict) -> list[dict]:
    """One ``siblings[]`` record per collected member, with its connection's ground truth."""
    conns = {c["conn_id"]: c for g in plan["groups"] for c in g["connections"]}
    out = []
    for member in collected["members"]:
        record = dict(member)
        conn = conns.get(member.get("conn_id"))
        if conn is not None:
            gt = conn["gt"]
            record["ssh" if "K_hex" in gt else "gocryptfs"] = gt
        out.append(record)
    return out


def cmd_siblings(frags: str, plan_path: str, collected_path: str) -> None:
    plan = _read_json(plan_path)
    for record in sibling_records(plan, _read_json(collected_path)):
        _append(frags, "siblings", record)
    for group in plan["groups"]:
        for conn in group["connections"]:
            for name, hexval in sorted(conn["secrets"].items()):
                cmd_key(frags, f"siblings.{conn['conn_id']}.{name}",
                        f"sibling-{group['group']}-{name}", hexval,
                        f"siblings:{group['group']}:{conn['conn_id']}")


def ecryptfs_fekek(passphrase: str) -> tuple[str, str]:
    digest = hashlib.sha512(ECRYPTFS_DEFAULT_SALT + passphrase.encode()).digest()
    for _ in range(ECRYPTFS_HASH_ROUNDS - 1):
        digest = hashlib.sha512(digest).digest()
    signature = hashlib.sha512(digest).hexdigest()[:16]
    return digest.hex(), signature


def cmd_ecryptfs_fekek(passphrase: str) -> None:
    fekek, sig = ecryptfs_fekek(passphrase)
    print(fekek, sig)


def _kernel_info() -> dict:
    uname = os.uname()
    try:
        with open("/proc/cmdline", encoding="utf-8") as fh:
            cmdline = fh.read().strip()
    except OSError:
        cmdline = None
    return {
        "release": uname.release, "version": uname.version,
        "uname_a": " ".join([uname.sysname, uname.nodename, uname.release,
                             uname.version, uname.machine]),
        "cmdline": cmdline,
    }


def cmd_finalize(frags: str, out: str, arch: str = "") -> None:
    doc: dict = {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).replace(microsecond=0)
        .isoformat().replace("+00:00", "Z"),
        "kernel": _kernel_info(),
        "arch": arch or platform.machine(),
        "btf_offsets": {},
    }
    for section in LIST_SECTIONS:
        doc[section] = []
    if os.path.exists(frags):
        with open(frags, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                section, record = entry["section"], entry["record"]
                if section == "btf_offsets":
                    doc["btf_offsets"].update(record)
                elif section == "kernel_extra":
                    doc["kernel"].update(record)
                else:
                    doc.setdefault(section, []).append(record)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")
    os.replace(tmp, out)


COMMANDS = {
    "add": cmd_add, "key": cmd_key, "kernel": cmd_kernel, "wg": cmd_wg,
    "gap": cmd_gap, "btf": cmd_btf, "ssh-tier-a": cmd_ssh_tier_a,
    "ecryptfs-fekek": cmd_ecryptfs_fekek, "finalize": cmd_finalize,
    "sibling-plan": cmd_sibling_plan, "siblings": cmd_siblings,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    COMMANDS[sys.argv[1]](*sys.argv[2:])
