"""Synthetic fixture dataset generator for integration tests.

Creates a deterministic dataset with known secrets at known offsets
for TLS 1.2 (openssl) and TLS 1.3 (boringssl) scenarios.
"""

from pathlib import Path

DATASET_ROOT = Path(__file__).parent / "dataset"
DUMP_SIZE = 512

# --- TLS 1.2 (openssl) ---
TLS12_SECRET_VALUE = bytes(range(32))
TLS12_SECRET_OFFSET = 64
TLS12_IDENTIFIER = bytes(range(32, 64))

# --- TLS 1.3 (boringssl) ---
TLS13_SECRET_TYPES = [
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
]
TLS13_OFFSETS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": 64,
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": 128,
    "CLIENT_TRAFFIC_SECRET_0": 192,
    "SERVER_TRAFFIC_SECRET_0": 256,
    "EXPORTER_SECRET": 320,
}
TLS13_SECRET_VALUES = {
    st: bytes([i + 0xA0] * 32) for i, st in enumerate(TLS13_SECRET_TYPES)
}
TLS13_IDENTIFIER = bytes([0x50] * 32)


def _xor_secret(base, run_num):
    """Derive per-run unique secret with high inter-run variance.

    Uses addition with run_num*128 to guarantee byte differences of 128
    between runs (variance ~4096, well above key_candidate threshold of 3000).
    Positional offset j*3 ensures non-uniform output to prevent cross-secret collisions.
    """
    return bytes([(b + run_num * 128 + j * 3) & 0xFF for j, b in enumerate(base)])


# Per-run secret values (XOR'd with run number)
TLS12_SECRET_VALUES_BY_RUN = {
    1: _xor_secret(TLS12_SECRET_VALUE, 1),
    2: _xor_secret(TLS12_SECRET_VALUE, 2),
}
TLS13_SECRET_VALUES_BY_RUN = {
    run_num: {st: _xor_secret(val, run_num) for st, val in TLS13_SECRET_VALUES.items()}
    for run_num in (1, 2)
}

# --- SSH 2 (openssh) ---
SSH2_SECRET_TYPES = [
    "SSH2_SESSION_KEY",
    "SSH2_SESSION_ID",
    "SSH2_ENCRYPTION_KEY_CS",
    "SSH2_ENCRYPTION_KEY_SC",
]
SSH2_OFFSETS = {
    "SSH2_SESSION_KEY": 64,
    "SSH2_SESSION_ID": 128,
    "SSH2_ENCRYPTION_KEY_CS": 192,
    "SSH2_ENCRYPTION_KEY_SC": 256,
}
SSH2_SECRET_VALUES = {
    st: bytes([i + 0xC0] * 32) for i, st in enumerate(SSH2_SECRET_TYPES)
}
SSH2_IDENTIFIER = bytes([0x70] * 32)

SSH2_SECRET_VALUES_BY_RUN = {
    run_num: {st: _xor_secret(val, run_num) for st, val in SSH2_SECRET_VALUES.items()}
    for run_num in (1, 2)
}

# Phase specs: (timestamp, prefix, name)
_TLS12_PHASES = [
    ("20240101_120000_000001", "pre", "handshake"),
    ("20240101_120001_000002", "post", "handshake"),
    ("20240101_120002_000003", "pre", "abort"),
    ("20240101_120003_000004", "post", "abort"),
]

_TLS13_PHASES = [
    ("20240101_120000_000001", "pre", "handshake"),
    ("20240101_120001_000002", "post", "handshake"),
    ("20240101_120002_000003", "pre", "abort"),
    ("20240101_120003_000004", "post", "abort"),
    ("20240101_120004_000005", "pre", "cleanup"),
    ("20240101_120005_000006", "post", "cleanup"),
]

_SSH2_PHASES = [
    ("20240101_120000_000001", "pre", "handshake"),
    ("20240101_120001_000002", "post", "handshake"),
    ("20240101_120002_000003", "pre", "disconnect"),
    ("20240101_120003_000004", "post", "disconnect"),
]


def _make_dump(size, secrets, pad):
    """Build a dump: pad byte everywhere, then overlay secrets at offsets."""
    data = bytearray([pad] * size)
    for offset, value in secrets.items():
        data[offset:offset + len(value)] = value
    return bytes(data)


def _tls12_secrets_for_phase(phase_name, run_num=1):
    """Return {offset: value} dict for a TLS 1.2 phase."""
    if phase_name == "post_abort":
        return {}
    return {TLS12_SECRET_OFFSET: TLS12_SECRET_VALUES_BY_RUN[run_num]}


def _tls13_secrets_for_phase(phase_name, run_num=1):
    """Return {offset: value} dict for a TLS 1.3 phase."""
    run_vals = TLS13_SECRET_VALUES_BY_RUN[run_num]
    all_secrets = {off: run_vals[st] for st, off in TLS13_OFFSETS.items()}
    handshake_types = {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"}

    if phase_name in ("pre_handshake", "post_handshake"):
        return all_secrets
    if phase_name in ("pre_abort", "post_abort"):
        return {off: val for st, (off, val) in
                zip(TLS13_OFFSETS.keys(), zip(TLS13_OFFSETS.values(), [run_vals[s] for s in TLS13_OFFSETS]))
                if st not in handshake_types}
    if phase_name == "pre_cleanup":
        return {TLS13_OFFSETS["EXPORTER_SECRET"]: run_vals["EXPORTER_SECRET"]}
    return {}


def _ssh2_secrets_for_phase(phase_name, run_num=1):
    """Return {offset: value} dict for an SSH 2 phase."""
    run_vals = SSH2_SECRET_VALUES_BY_RUN[run_num]
    if phase_name in ("pre_handshake", "post_handshake"):
        return {off: run_vals[st] for st, off in SSH2_OFFSETS.items()}
    if phase_name == "pre_disconnect":
        return {SSH2_OFFSETS["SSH2_SESSION_KEY"]: run_vals["SSH2_SESSION_KEY"]}
    return {}


def _write_keylog(run_dir, secret_type_values, identifier):
    """Write keylog.csv with header 'line'."""
    lines = ["line"]
    id_hex = identifier.hex()
    for stype, sval in secret_type_values:
        lines.append(f"{stype} {id_hex} {sval.hex()}")
    (run_dir / "keylog.csv").write_text("\n".join(lines) + "\n")


def _create_runs(lib_dir, lib_name, version, phases, secrets_fn, identifier, secret_entries_fn):
    """Create run_1 and run_2 with different padding and per-run secrets."""
    for run_num, pad in [(1, 0x00), (2, 0xFE)]:
        run_dir = lib_dir / f"{lib_name}_run_{version}_{run_num}"
        run_dir.mkdir(parents=True)
        for ts, prefix, name in phases:
            phase_key = f"{prefix}_{name}"
            secrets = secrets_fn(phase_key, run_num)
            dump = _make_dump(DUMP_SIZE, secrets, pad)
            (run_dir / f"{ts}_{prefix}_{name}.dump").write_bytes(dump)
        _write_keylog(run_dir, secret_entries_fn(run_num), identifier)


def _ensure_ssh_fixtures(root):
    """Add SSH fixtures to an existing dataset without regenerating TLS data."""
    ssh_dir = root / "SSH2"
    if ssh_dir.exists():
        return root
    openssh_dir = ssh_dir / "scenario_a" / "openssh"
    _create_runs(
        openssh_dir, "openssh", "2", _SSH2_PHASES, _ssh2_secrets_for_phase,
        SSH2_IDENTIFIER,
        lambda run_num: [(st, SSH2_SECRET_VALUES_BY_RUN[run_num][st]) for st in SSH2_SECRET_TYPES],
    )
    return root


def generate_dataset(root=DATASET_ROOT):
    """Generate the complete fixture dataset. Idempotent: skips if exists."""
    if root.exists():
        _ensure_ssh_fixtures(root)
        return root

    # TLS 1.2 openssl
    openssl_dir = root / "TLS12" / "scenario_a" / "openssl"
    _create_runs(
        openssl_dir, "openssl", "12", _TLS12_PHASES, _tls12_secrets_for_phase,
        TLS12_IDENTIFIER,
        lambda run_num: [("CLIENT_RANDOM", TLS12_SECRET_VALUES_BY_RUN[run_num])],
    )

    # TLS 1.3 boringssl
    boringssl_dir = root / "TLS13" / "scenario_a" / "boringssl"
    _create_runs(
        boringssl_dir, "boringssl", "13", _TLS13_PHASES, _tls13_secrets_for_phase,
        TLS13_IDENTIFIER,
        lambda run_num: [(st, TLS13_SECRET_VALUES_BY_RUN[run_num][st]) for st in TLS13_SECRET_TYPES],
    )

    # SSH 2 openssh (reuse _ensure_ssh_fixtures to avoid duplication)
    _ensure_ssh_fixtures(root)

    return root


if __name__ == "__main__":
    path = generate_dataset()
    print(f"Dataset generated at: {path}")
