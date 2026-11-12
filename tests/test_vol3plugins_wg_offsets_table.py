"""The built-in x86_64 WireGuard offset table (``vol3plugins/linux/secrets/wg_offsets.py``).

Every ``("x86_64", kver)`` entry added from distribution packages was computed from the
official ``wireguard.ko`` module BTF (split on top of the vmlinux BTF of the same package) and
checked member by member against real ``pahole -C`` output.  These tests pin that table: each
entry is complete, internally consistent, looked up as ``btf``, and a few pahole values per
series are pinned so that an accidental edit of a shared members dict is caught.

Stdlib + the module under test only (no volatility3 needed).
"""

import pytest

from memdiver.vol3plugins.linux.secrets import wg_offsets

# Keys whose member is a 32-byte key array: no other read member may start inside it.
KEY_ARRAYS = (
    "noise_static_identity.static_public", "noise_static_identity.static_private",
    "noise_handshake.ephemeral_private", "noise_handshake.remote_static",
    "noise_handshake.remote_ephemeral", "noise_handshake.precomputed_static_static",
    "noise_handshake.preshared_key", "noise_handshake.hash", "noise_handshake.chaining_key",
    "noise_symmetric_key.key", "cookie_checker.cookie_encryption_key",
    "cookie_checker.message_mac1_key", "cookie.cookie_decryption_key", "cookie.message_mac1_key",
)

# Source-declaration order of the members the plugin reads (identical in every kernel sampled).
DECLARED_ORDER = {
    "wg_device": ("dev", "creating_net", "static_identity", "cookie_checker", "device_list",
                  "peer_list", "num_peers", "fwmark", "incoming_port"),
    "wg_peer": ("device", "is_dead", "keypairs", "endpoint", "handshake", "latest_cookie", "rx_bytes",
                "tx_bytes", "timer_handshake_attempts", "persistent_keepalive_interval",
                "walltime_last_handshake", "peer_list", "allowedips_list", "internal_id"),
}

# kver -> pahole values (x86_64 module BTF, pahole v1.30), a few per distinct layout.
PAHOLE_SPOT_CHECKS = {
    "5.15.0-25-generic": {"sizeof(wg_peer)": 1552, "wg_peer.internal_id": 1544,
                          "noise_handshake.preshared_key": 184, "noise_keypair.receiving": 88},
    "5.15.0-203-generic": {"wg_device.cookie_checker": 992, "sizeof(wg_device)": 1344,
                           "allowedips_node.peer_list": 56},
    "6.1.0-9-amd64": {"wg_peer.handshake": 240, "noise_keypair.remote_index": 1176,
                      "cookie.message_mac1_key": 74},
    "6.1.0-54-cloud-amd64": {"wg_peer.walltime_last_handshake": 1072, "sizeof(wg_peer)": 1552},
    "6.8.0-31-generic": {"wg_device.static_identity": 856, "noise_handshake.chaining_key": 248},
    "6.8.0-149-generic": {"sizeof(wg_peer)": 1552, "cookie_checker.device": 144},
    "5.14.0-162.6.1.el9_1.x86_64": {"wg_peer.timer_handshake_attempts": 1144,
                                    "wg_peer.internal_id": 1640, "sizeof(wg_peer)": 1648},
    "5.14.0-362.24.1.el9_3.x86_64": {"wg_peer.peer_list": 1192, "wg_peer.handshake": 240},
    "5.14.0-427.16.1.el9_4.x86_64": {"wg_peer.internal_id": 1672, "sizeof(wg_peer)": 1680,
                                     "wg_peer.allowedips_list": 1208},
    "5.14.0-570.58.1.el9_6.x86_64": {"wg_peer.internal_id": 1672, "noise_keypair.internal_id": 1208},
    "5.14.0-611.55.1.el9_7.x86_64": {"wg_peer.internal_id": 1696, "sizeof(wg_peer)": 1704},
    "5.14.0-687.66.1.el9_8.x86_64": {"wg_peer.internal_id": 1760, "sizeof(wg_peer)": 1768,
                                     "wg_peer.walltime_last_handshake": 1152},
    "6.11.0-29-generic": {"sizeof(wg_peer)": 1552, "noise_handshake.remote_index": 292},
    "6.14.0-37-generic": {"wg_peer.internal_id": 1576, "sizeof(wg_peer)": 1584},
    "6.17.0-44-generic": {"wg_peer.internal_id": 1640, "sizeof(wg_device)": 1344},
    "7.0.0-43-generic": {"wg_peer.internal_id": 1640, "noise_static_identity.has_identity": 104},
    "6.17.1-300.fc43.x86_64": {"wg_peer.internal_id": 1640, "sizeof(wg_peer)": 1648,
                               "wg_peer.peer_list": 1112},
    "7.2.15-100.fc43.x86_64": {"wg_device.cookie_checker": 984, "sizeof(wg_device)": 1280,
                               "noise_static_identity.has_identity": 96, "cookie_checker.device": 136,
                               "wg_peer.latest_cookie": 672, "sizeof(wg_peer)": 1648},
}

X86_ENTRIES = sorted(kver for arch, kver in wg_offsets.WG_OFFSETS if arch == "x86_64")


def test_the_contest_kernels_have_exact_entries():
    assert len(X86_ENTRIES) >= 30
    for kver in PAHOLE_SPOT_CHECKS:
        assert ("x86_64", kver) in wg_offsets.WG_OFFSETS, kver


@pytest.mark.parametrize("kver", X86_ENTRIES)
def test_entry_is_complete_and_btf(kver):
    entry = wg_offsets.WG_OFFSETS[("x86_64", kver)]
    assert entry.missing() == ()
    assert set(entry.members) == set(wg_offsets.REQUIRED_KEYS)
    assert set(entry.sources.values()) == {"btf"}
    assert kver in entry.source and entry.source.startswith("btf:wireguard x86_64")
    looked_up = wg_offsets.lookup_offsets("x86_64", kver)
    assert looked_up is entry
    assert looked_up.key_path_guessed() == () and looked_up.untrusted_no_oracle() == ()


@pytest.mark.parametrize("kver", X86_ENTRIES)
def test_entry_is_internally_consistent(kver):
    members = wg_offsets.WG_OFFSETS[("x86_64", kver)].members
    for struct_name in ("wg_device", "wg_peer"):
        size = members["sizeof(%s)" % struct_name]
        offsets = [members["%s.%s" % (struct_name, m)] for m in DECLARED_ORDER[struct_name]]
        assert offsets == sorted(set(offsets)), (struct_name, offsets)  # strictly increasing
        assert all(0 <= o < size for o in offsets)
    assert members["wg_device.dev"] == 0 and members["wg_peer.device"] == 0  # back-pointers first
    for key in KEY_ARRAYS:
        struct_name, start = key.split(".", 1)[0], members[key]
        inside = [k for k, v in members.items()
                  if k != key and k.startswith(struct_name + ".") and start <= v < start + 32]
        assert inside == [], (key, inside)
    assert members["sizeof(wg_device)"] % 64 == 0  # wg_device is ____cacheline_aligned


@pytest.mark.parametrize("kver", sorted(PAHOLE_SPOT_CHECKS))
def test_pinned_pahole_values(kver):
    members = wg_offsets.WG_OFFSETS[("x86_64", kver)].members
    for key, value in PAHOLE_SPOT_CHECKS[kver].items():
        assert members[key] == value, (kver, key)


def test_unknown_kernels_stay_derived_guesses():
    for kver in ("5.15.0-999-generic", "5.14.0-999.1.1.el9_9.x86_64", "6.8.0-90-generic"):
        derived = wg_offsets.lookup_offsets("x86_64", kver)
        assert "derived" in derived.source
        assert set(derived.key_path_guessed()) == set(wg_offsets.KEY_PATH_KEYS)
        assert set(derived.untrusted_no_oracle()) == set(wg_offsets.NO_ORACLE_KEYS)


def test_unknown_rhel9_kernel_is_derived_from_a_rhel9_entry():
    derived = wg_offsets.lookup_offsets("x86_64", "5.14.0-999.1.1.el9_9.x86_64")
    nearest = derived.source.split(" for ")[0].rsplit(" ", 1)[1]
    assert nearest.startswith("5.14.0-") and ".el9" in nearest
    assert derived.members == wg_offsets.WG_OFFSETS[("x86_64", nearest)].members
