"""``make validate``: the claim gate of the Volatility 3 plugin entry.

Every claim below is a pytest test named after its claim ID. A claim runs the real plugin under
a real ``vol`` and compares its output with ground truth that does NOT come from the plugin.
The in-repo sample claims need no environment variable; the capture claims skip cleanly
without ``MEMDIVER_SECRETS_CORPUS``. A claim table (claim, vol version, result, seconds) is
printed at the end of the run.

Claims
------
=========  ==============================================================================  ======
ID         Exact claim (what passing proves)                                                Data
=========  ==============================================================================  ======
C-MSL1     MSL layer parity: stock vol stacks the ``.msl`` slice (``MslStacker``) and       sample
           ``regexscan.RegExScan`` finds the master key at exactly the VAs where
           MemDiver's own ``MslDumpSource`` finds it (and where ``samples.json`` says);
           ``msl.info`` reports the captured PID, 1 region and ``Integrity valid``.
C-MSL2     Encrypted ``.msl``: with ``MEMDIVER_MSL_KEY_FILE`` the encrypted, zstd-          sample
           compressed copy gives the SAME plugin rows (offset, key, Proven, Scope) as the
           plaintext slice; without the key file no row is proven.
C-MSL3     Tamper evidence: one flipped byte in the first key copy makes ``msl.info``      sample
           report ``Integrity BROKEN`` and the synthesized plugin print that copy as
           ``rejected`` while the intact copy is still ``oracle:gocryptfs-gcm``.
C-MSL4     ``msl.*`` plugins: on every in-repo slice ``msl.pagemap`` / ``msl.modules`` /      sample
           ``msl.threads`` / ``msl.keyhints`` equal what MemDiver's own reader decodes
           (page-state runs, module set, thread ids, hint count); ``msl.verify`` says
           ``valid`` on every intact slice and ``tampered`` on the tampered one, naming the
           VAS_MAP block that follows the modified region as the one broken link. Under a
           BARE stock vol (``MEMDIVER_VOL3_BARE_VOL``: no MemDiver, no blake3) the same four
           plugins and ``msl.info`` (except the Integrity row) give identical rows, and
           ``msl.verify`` says ``not verified: needs memdiver (BLAKE3``.
C-SYN1     Synthesis: ``synthesize_vol3_plugin`` builds a plugin from the two in-repo     sample
           slices (aes-gcm + xchacha, one key each) whose own verdict is ``proven``;
           that fresh plugin, run under vol on each slice with the slice's vault oracle
           sample, proves exactly the slice's key at exactly its key VAs, Scope
           ``msl:<pid>``.
C-SYN2     No-MemDiver path: the committed ``samples/plugins/memdiver_gocryptfs.py`` run   sample
           under a stock vol whose interpreter has NEITHER MemDiver NOR a crypto library
           (``MEMDIVER_VOL3_BARE_VOL``; pure-Python oracle) proves both slices' keys with
           Scope ``msl:<pid>`` (the ``.msl`` is stacked by the slim pure-Python reader).
C-IMP1     Import hygiene: no module-level import outside stdlib + volatility3 in any      repo
           ``vol3plugins/**`` file or the sample plugin (AST rule); ``vol -p vol3plugins
           -h`` best-of-3 < 1.5 s and lists our plugins; importing every plugin the vol
           way leaves no ``memdiver`` module loaded.
C-DM1      ``linux.dmcrypt``: every dm-crypt device of the capture (LUKS1, LUKS2,           capture
           VeraCrypt) is found and its volume key equals the guest's ground truth byte
           for byte; ``--export dmsetup`` is identical to ``dmsetup table --showkeys``.
C-DM2      ``linux.dmcrypt`` proofs: every key is ``proven``; LUKS keys by                 capture
           ``O1+O2[+O3]:luks-digest[+<evidence>]`` (key schedule in the tfm context AND the
           on-disk LUKS digest from the page cache), VeraCrypt by ``O1+O3:<fs|pagecache-
           pair>`` (its loop-backing ciphertext pages decrypt to the resident dm plaintext
           page or to a filesystem head), never by ``O1`` alone.
C-DM3      Offsets from memory: with the built-in offset table hidden                     capture
           (``MEMDIVER_TEST_HIDE_OFFSET_TABLE=1``) the offsets come from the kernel's own
           in-memory module BTF and the dmsetup export is still identical.
C-WG1      ``linux.wireguard``: both interfaces' private keys, every peer public key,      capture
           endpoint, allowed IPs and the PSK equal ``wg show all dump``; identities and
           peers ``proven`` (O_id/O_mac1/O_dh + back-pointer); no guessed offsets.
C-WG2      WireGuard handshake state: the in-flight handshake (peer with no completed     capture
           handshake) is proven via O_ck (recomputed Noise chaining key); the PSK is
           ``PSK:bound-to-proven-peer``; transport keys are reported ``unverified``
           (no memory-only oracle exists) and are never claimed proven.
C-WG3      Keylog export: ``--export keylog`` is Wireshark's WireGuard grammar (only the   capture
           four key types, 44-char base64, PSK only right after an ephemeral line), its
           static private keys are the ground-truth ones, and the transport JSON holds
           no key bytes.
C-KR1      ``linux.keyring``: the ``key_serial_tree`` walk reproduces the guest's          capture
           ``/proc/keys`` (type + description; at most 2 keys garbage-collected before
           the dump) and proves the eCryptfs auth token (``ecryptfs-sig``) whose payload
           starts with the ground-truth FEKEK.
C-KR2      ``linux.keyring`` on capture v2b: the ``user cryptsetup:<uuid>-d0`` key         capture
           (``cryptsetup --link-vk-to-keyring``) is ``proven`` by ``[dmcrypt-cross]``; its
           payload equals the sidecar's LUKS2 volume key AND the key ``linux.dmcrypt``
           proves for that device. The ``logon fscrypt:<desc>`` legacy key decodes as
           ``struct fscrypt_key`` (mode 1, size 64), its raw key equals the v1 master
           key and its descriptor is ``SHA-512(SHA-512(raw))[:8]`` (``[fscrypt-desc]``,
           recomputed here with hashlib).
C-FS1      ``linux.fscrypt`` v1: the master key equals ground truth and is proven by       capture
           re-deriving every open inode's per-file key against its tfm schedule.
C-FS2      ``linux.fscrypt`` v2: the HKDF-PRK HMAC-SHA512 midstates equal the ones         capture
           computed from the ground-truth key and the key identifier is re-derived from
           them (``oracle:identifier+per-file-schedule``).
C-FS3      ``linux.fscrypt`` per-file proof is complete: every decrypted inode of both     capture
           policies matched (``Inodes`` m/n with m == n > 0); policy, device, fs type,
           modes and flags equal ground truth; offsets from the ISF.
C-FS4      ``linux.fscrypt`` v1 descriptor cross-check on capture v2b (descriptor       capture
           derived from the key): the v1 master key is proven by
           ``oracle:descriptor+per-file-schedule`` and equals ground truth; the
           descriptor equals ``SHA-512(SHA-512(key))[:8]`` (hashlib) and the sidecar's.
C-EC1      ``linux.ecryptfs``: every open eCryptfs file's FEK is proven by                 capture
           ``oracle:ecryptfs-root-iv+tfm-schedule``; mount point, lower dir and the
           auth-token signature equal ground truth, and the auth token is joined to a
           ``keyring proven`` row of linux.keyring.
C-EC2      ``linux.ecryptfs`` tag-3 proof inside the plugin: on BOTH x86 captures every     capture
           FEK row is ``oracle:ecryptfs-root-iv+tfm-schedule+ecryptfs-tag3`` (the lower
           file's header, read from the page cache, unwraps to the FEK under the mount's
           FEKEK); ``--export fekek`` is exactly ``<sig> <fekek_hex>`` of the guest's
           ground truth; ``--export fek`` lists one row per file whose FEK equals the
           tag-3 packet of the lower header that STOCK ``linux.pagecache.InodePages
           --dump`` recovers, decrypted with the ground-truth FEKEK (AES-ECB).
C-LA57     5-level paging: on the LA57 twin capture, with ``-p vol3plugins``               capture
           (``LinuxLA57IntelStacker``), ``linux.pslist`` lists the processes (>= 100,
           incl. the gocryptfs daemon) and ``linux.dmcrypt`` gives the same ground-truth
           keys, all proven.
C-MOUNT1   Mount proof (capture v2b): ``tools/vol3_capture/mount_proof.sh`` runs the       capture
           plugins on the v2b image and, in Docker, opens the capture's REAL containers
           with only the plugin-exported keys: LUKS1/LUKS2/VeraCrypt via the exact
           ``--export dmsetup`` table (device path adjusted; LUKS2's keyring reference
           filled from ``--export masterkey``) AND via the generated ``--export
           cryptsetup`` scripts; fscrypt v1 via the kernel ioctl; gocryptfs via FUSE with
           the synthesized sample plugin's proven key; fscrypt v2 (HKDF-PRK midstates),
           eCryptfs (FEKs) and LUKS2/VeraCrypt also decrypted in userspace. Every planted
           file's sha256 equals ``samples.sha256`` and no loop device is left behind.
           Skips without the v2b stem or a working ``docker info``.
C-SSH1     ``memdiver.ssh.SSHKeys``. In-repo libssh + wolfSSH slices: Tier A               sample
           ``oracle:ssh-kdf-consistency`` for all six keys A-F, equal to ``samples.json``.
           Both x86 captures: the OpenSSH client and the                                    capture
           post-auth sshd each give Tier B rows for c2s and s2c whose 64-byte keys are
           identical across the two processes, cipher = the sidecar's; the Dropbear
           server's Tier C ChaCha pairs equal its OpenSSH client's keys per direction;
           all ``unverified`` (K is wiped), none proven. With ``MEMDIVER_SSH_CORPUS``
           (``.msl`` client slices + ``gt.json`` from the implementations' own key
           hooks): every Go/libssh/wolfSSH slice gives Tier A ``oracle:ssh-kdf-consistency``
           with >= 2 letters, every proven key equal to ground truth; Paramiko (drops
           K after NEWKEYS) gives no proven row.                                            slices
C-SSH2     ``memdiver.ssh.SSHKeys --pid`` on the x86 v2b full image: the libssh 0.10.6     capture
           client gives Tier A ``oracle:ssh-kdf-consistency`` for all six keys A-F, each
           byte-equal (and of equal length) to the sidecar's ``ssh_tier_a`` keys, cipher
           and MAC = the sidecar's negotiated names (``lengths: negotiated(libssh)``);
           its Paramiko peer (drops K after NEWKEYS) gives no proven row.
C-WGGO1    ``memdiver.wireguard_go.WireGuardGo``. In-repo wireguard-go slice: static       sample
           key ``oracle:x25519-pubkey``, peer ``oracle:x25519-dh-consistency``, ephemeral
           ``oracle:noise-chaining-key``, transport keys ``unverified``, all equal to
           ``samples.json`` at its VAs; the keylog export's static key is the ground
           truth and its transport JSON holds no key bytes. With
           ``MEMDIVER_WG_GO_CORPUS``: on EVERY wireguard-go archive run (both roles, the     dumps
           ``post_active`` dump converted to ``.msl``) the static key is proven and equals
           the in-process keylog, the peer key likewise (trusted ``device_backpointer``),
           no row is ``rejected`` and every transport key equals the keylog, unverified.
C-WGGO2    ``memdiver.wireguard_go.WireGuardGo`` preshared key on REAL data: the        sample
           in-repo PSK slice (responder caught in ``responseCreated``, rig run with
           ``WG_PRESHARED_KEY``) gives the static key ``oracle:x25519-pubkey``, the peer
           ``oracle:x25519-dh-consistency``, the ephemeral AND the ``preshared`` row
           ``oracle:noise-chaining-key``, each equal to ``samples.json`` (the in-process
           keylog) at its VA; ``--export keylog`` has ``PRESHARED_KEY`` = the ground-truth
           PSK right after the ephemeral line.
C-SIB1     ``memdiver.page_sharing.PageSharing`` on capture v2b (sibling groups of the     capture
           sidecar's ``siblings[]``): ``--pid <the 17 members> --group`` gives exactly the
           three groups (dropbear ``forked``, gocryptfs ``independent``, OpenSSH ``mixed``:
           re-exec'd monitors, each with its forked session), build-ids = the sidecar's;
           per member ``PrivateDirtyKB`` == the guest's ``smaps_rollup`` Private_Dirty and
           ``RssKB`` == Rss + 4 (the PFNMAP ``[vvar]`` page smaps skips); every ground-truth
           secret page (38) lies in a ``private_*`` run of ``--dump``'s
           ``pagesharing.json``. ``--comm dropbear sshd gocryptfs --group`` finds the same
           three identities (plus the capture's earlier instances of each binary).
=========  ==============================================================================  ======

Environment
-----------
* ``MEMDIVER_VOL3_VOL`` (or ``MEMDIVER_VOL3_BIN``): the stock ``vol`` (a ``vol`` executable or a
  ``vol.py``); default: the ``vol`` beside this interpreter, else ``vol`` on PATH.
* ``MEMDIVER_VOL3_ALT_VOL_PY``: a second volatility3 tree's ``vol.py`` (e.g. 2.28.2), run with
  this interpreter. Every claim runs once per tree that is present.
* ``MEMDIVER_VOL3_BARE_VOL``: a ``vol`` whose interpreter has neither MemDiver nor a crypto
  library (C-SYN2 and C-MSL4's bare part).
* ``MEMDIVER_SECRETS_CORPUS``: absolute directory of the x86_64 acquired-secrets captures
  (``<stem>.{lime,isf.json,secrets.json,secrets.tar.gz}``).
* ``MEMDIVER_SSH_CORPUS``: directory of SSH ``.msl`` capture sessions, each ``<session>/gt.json``
  (C-SSH1 Tier A part).
* ``MEMDIVER_WG_GO_CORPUS``: the WireGuard rig's ``archive`` directory (``run_*/<role>/{dumps,
  keylogs}``, see ``tests/_wg_go_corpus.py``; C-WGGO1 corpus part).

Every vol run gets a fresh, pre-created ``--cache-path`` (one per tree and image per session).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLUGINS = REPO / "vol3plugins"
SAMPLES = REPO / "samples"
SAMPLE_PLUGINS = SAMPLES / "plugins"
SAMPLE_PLUGIN = "memdiver_gocryptfs.MemDiverSynthGocryptfs"
ORACLE_KIND = "gocryptfs-gcm"
PROVEN = "oracle:" + ORACLE_KIND
CORPUS = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
STEM_4LEVEL = "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic"
STEM_LA57 = "ubuntu-24.04-secrets-x86-la57_6.8.0-136-generic"
# Capture v2b (a superset of v2; v2 itself stays local-only and is not published). Every claim
# that needs the v2-era sidecar items (keyring_vk, fscrypt v1 logon key, ssh_tier_a,
# containers.tar) uses this ONE stem; per-capture values (PIDs, keys) come from its sidecar.
STEM_V2B = "ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic"
HIDE_TABLE_ENV = "MEMDIVER_TEST_HIDE_OFFSET_TABLE"
KEY_FILE_ENV = "MEMDIVER_MSL_KEY_FILE"
SCRUBBED_ENV = ("PYTHONPATH", KEY_FILE_ENV, "MEMDIVER_MSL_KEM_KEY_FILE", "MEMDIVER_MSL_PASSPHRASE",
                HIDE_TABLE_ENV)
VOL_TIMEOUT_S = 1800
BANNER = re.compile(r"Volatility 3 Framework (\S+)")


# --------------------------------------------------------------------------- vol trees


def _launcher(path: str) -> list:
    return [sys.executable, path] if path.endswith(".py") else [path]


def _stock_vol():
    configured = os.environ.get("MEMDIVER_VOL3_VOL") or os.environ.get("MEMDIVER_VOL3_BIN")
    beside = Path(sys.executable).with_name("vol")
    found = configured or (str(beside) if beside.is_file() else shutil.which("vol"))
    return _launcher(found) if found and Path(found).is_file() else None


def _alt_vol():
    alt = os.environ.get("MEMDIVER_VOL3_ALT_VOL_PY", "")
    return _launcher(alt) if alt and Path(alt).is_file() else None


def _bare_vol():
    bare = os.environ.get("MEMDIVER_VOL3_BARE_VOL", "")
    return [bare] if bare and Path(bare).is_file() else None


TREES = {"stock": _stock_vol, "alt": _alt_vol}
TREE_ENV = {"stock": "MEMDIVER_VOL3_VOL / vol", "alt": "MEMDIVER_VOL3_ALT_VOL_PY",
            "bare": "MEMDIVER_VOL3_BARE_VOL"}


# --------------------------------------------------------------------------- claim table


class ClaimTable:
    """Collects (claim, vol version, result, seconds) from the test reports; prints them last."""

    def __init__(self) -> None:
        self.rows = {}

    def pytest_runtest_logreport(self, report) -> None:
        props = dict(report.user_properties)
        if "claim" not in props:
            return
        key = report.nodeid
        row = self.rows.setdefault(key, {"claim": props["claim"], "result": "passed", "seconds": 0.0})
        row["vol"] = props.get("vol", row.get("vol", "-"))
        row["seconds"] += report.duration
        if report.skipped:
            row["result"] = "skipped"
        elif report.failed:
            row["result"] = "FAILED" if report.when == "call" else "ERROR"
        elif report.when == "call" and hasattr(report, "wasxfail"):
            row["result"] = "xfail"

    def pytest_terminal_summary(self, terminalreporter) -> None:
        if not self.rows:
            return
        terminalreporter.write_sep("=", "MemDiver vol3 claim table")
        terminalreporter.write_line("%-8s %-16s %-8s %8s" % ("claim", "vol", "result", "seconds"))
        for row in sorted(self.rows.values(), key=lambda r: (r["claim"], r["vol"])):
            terminalreporter.write_line("%-8s %-16s %-8s %8.1f" % (row["claim"], row["vol"], row["result"],
                                                                    row["seconds"]))


@pytest.fixture(scope="session", autouse=True)
def _claim_table(request):
    plugin = ClaimTable()
    request.config.pluginmanager.register(plugin, "memdiver-claim-table")
    yield plugin


@pytest.fixture
def claim(request):
    """``claim("C-X", tree)``: tag this test for the claim table."""

    def tag(claim_id: str, tree: str) -> None:
        request.node.user_properties.append(("claim", claim_id))
        request.node.user_properties.append(("vol", tree))

    def version(text: str) -> None:
        """Record the vol version: a banner text or a bare ``X.Y.Z``."""
        match = BANNER.search(text) or re.fullmatch(r"(\d+\.\d+\S*)", text.strip())
        if match:
            request.node.user_properties.append(("vol", match.group(1)))

    tag.version = version
    return tag


# --------------------------------------------------------------------------- vol runner


class Vol:
    """One vol tree with a fresh cache per image; runs are memoised for the session."""

    def __init__(self, name: str, argv: list, work: Path) -> None:
        self.name, self.argv, self.work = name, argv, work
        self.version = name
        self._done = {}

    def cache(self, image: Path) -> Path:
        cache = self.work / ("cache-" + hashlib.sha256(str(image).encode()).hexdigest()[:12])
        cache.mkdir(parents=True, exist_ok=True)
        return cache

    def run(self, image: Path, plugin_args: list, plugin_dirs=(PLUGINS,), symbols: Path = None,
            env: dict = None, renderer: str = "json", check: bool = True):
        """``(rows or text, output dir, completed process)`` of one vol run (memoised)."""
        key = (str(image), tuple(plugin_args), tuple(map(str, plugin_dirs)), str(symbols),
               tuple(sorted((env or {}).items())), renderer)
        if key in self._done:
            return self._done[key]
        out = self.work / ("out-%d" % len(self._done))
        out.mkdir()
        argv = list(self.argv) + ["-q", "-r", renderer, "--offline", "--cache-path", str(self.cache(image)),
                                  "-p", ";".join(map(str, plugin_dirs)), "-f", str(image), "-o", str(out)]
        if symbols is not None:
            argv[len(self.argv):len(self.argv)] = ["-s", str(symbols)]
        full_env = {k: v for k, v in os.environ.items() if k not in SCRUBBED_ENV}
        full_env.update(env or {})
        result = subprocess.run(argv + list(plugin_args), capture_output=True, text=True, cwd=str(out),
                                env=full_env, timeout=VOL_TIMEOUT_S)
        match = BANNER.search(result.stdout + result.stderr)
        if match:
            self.version = match.group(1) + ("-bare" if self.name == "bare" else "")
        if check:
            assert result.returncode == 0, (argv + list(plugin_args), result.stderr[-3000:])
        parsed = result.stdout
        if renderer == "json" and result.returncode == 0:
            parsed = json.loads(result.stdout[result.stdout.index("["):])
        self._done[key] = (parsed, out, result)
        return self._done[key]


@pytest.fixture(scope="session")
def vols(tmp_path_factory):
    trees = {}
    for name, find in list(TREES.items()) + [("bare", _bare_vol)]:
        argv = find()
        if argv is not None:
            trees[name] = Vol(name, argv, tmp_path_factory.mktemp("vol-" + name))
    return trees


def _tree(vols, name: str, claim) -> Vol:
    if name not in vols:
        pytest.skip("vol tree %r not present (%s)" % (name, TREE_ENV[name]))
    return vols[name]


def _proven(rows: list) -> list:
    return sorted((r["KeyOffset"], r["KeyHex"], r["Scope"]) for r in rows if r["Proven"] == PROVEN)


# --------------------------------------------------------------------------- in-repo samples


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    """``samples.json`` + the ``.msl`` files unpacked into a session dir, checksums verified."""
    sums = (SAMPLES / "SHA256SUMS").read_text().split("\n")
    for line in filter(None, sums):
        digest, name = line.split("  ", 1)
        assert _sha256(SAMPLES / name) == digest, "SHA256SUMS mismatch: " + name
    manifest = json.loads((SAMPLES / "samples.json").read_text())
    work = tmp_path_factory.mktemp("samples")
    paths = {}
    for entry in list(manifest["slices"].values()) + [manifest["tampered"]]:
        target = work / entry["msl"]
        with gzip.open(SAMPLES / entry["file"], "rb") as packed, open(target, "wb") as out:
            shutil.copyfileobj(packed, out, 1 << 20)
        assert _sha256(target) == entry["msl_sha256"], entry["file"]
        paths[entry["msl"]] = target
    return {"manifest": manifest, "paths": paths, "work": work}


def _slice(samples, cipher: str):
    entry = samples["manifest"]["slices"][cipher]
    return entry, samples["paths"][entry["msl"]]


def _expected_rows(entry) -> list:
    scope = "msl:%d" % entry["pid"]
    return sorted((int(va, 16), entry["master_key_hex"], scope) for va in entry["key_vas"])


def _plugin_rows(vol: Vol, image: Path, oracle: Path, plugin_dirs=(PLUGINS, SAMPLE_PLUGINS), env=None,
                 extra=()) -> list:
    rows, _out, _res = vol.run(image, [SAMPLE_PLUGIN, "--oracle-sample", str(oracle), *extra],
                               plugin_dirs=plugin_dirs, env=env)
    return rows


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_MSL1_layer_parity(tree, vols, samples, claim):
    claim("C-MSL1", tree)
    vol = _tree(vols, tree, claim)
    from memdiver.core.dump_source import MslDumpSource

    for cipher in ("aes", "xchacha"):
        entry, msl = _slice(samples, cipher)
        key = bytes.fromhex(entry["master_key_hex"])
        mine = []
        with MslDumpSource(msl) as source:
            for va, length, vas_offset in source.captured_runs():
                data = source.read_range(vas_offset, length, view="vas")
                mine += [va + m.start() for m in re.finditer(re.escape(key), data)]
        pattern = "".join("\\x%02x" % b for b in key)
        rows, _out, _res = vol.run(msl, ["regexscan.RegExScan", "--pattern", pattern])
        assert sorted(r["Offset"] for r in rows) == mine == [int(va, 16) for va in entry["key_vas"]]
        info, _out, result = vol.run(msl, ["msl.info"], renderer="quick")
        assert re.search(r"^PID\s+%d$" % entry["pid"], info, re.M), info
        assert re.search(r"^Regions\s+1$", info, re.M) and re.search(r"^Integrity\s+valid$", info, re.M), info
    claim.version(vol.version)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_MSL2_encrypted_slice(tree, vols, samples, claim):
    claim("C-MSL2", tree)
    vol = _tree(vols, tree, claim)
    entry, msl = _slice(samples, "aes")
    oracle = SAMPLES / entry["oracle_sample"]
    encrypted = SAMPLES / samples["manifest"]["encrypted"]["file"]
    key_file = SAMPLES / samples["manifest"]["encrypted"]["key_file"]
    plain = _plugin_rows(vol, msl, oracle)
    assert _proven(plain) == _expected_rows(entry)
    unlocked = _plugin_rows(vol, encrypted, oracle, env={KEY_FILE_ENV: str(key_file)})
    project = lambda rows: sorted((r["KeyOffset"], r["KeyHex"], r["Proven"], r["Scope"]) for r in rows)
    assert project(unlocked) == project(plain)
    locked, _out, result = vol.run(encrypted, [SAMPLE_PLUGIN, "--oracle-sample", str(oracle)],
                                   plugin_dirs=(PLUGINS, SAMPLE_PLUGINS), check=False)
    assert result.returncode != 0 or not [r for r in locked if r["Proven"] == PROVEN]
    claim.version(vol.version)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_MSL3_tamper_evidence(tree, vols, samples, claim):
    claim("C-MSL3", tree)
    vol = _tree(vols, tree, claim)
    entry, tampered = samples["manifest"]["tampered"], samples["paths"]["gocryptfs_aes_tampered.msl"]
    info, _out, _res = vol.run(tampered, ["msl.info"], renderer="quick")
    assert re.search(r"^Integrity\s+BROKEN", info, re.M), info
    rows = _plugin_rows(vol, tampered, SAMPLES / "gocryptfs_aes.oracle", extra=("--show-unverified",))
    verdicts = {r["KeyOffset"]: r["Proven"] for r in rows}
    assert verdicts[int(entry["flipped_va"], 16)] == "rejected"
    assert verdicts[int(entry["intact_key_va"], 16)] == PROVEN
    claim.version(vol.version)


# --------------------------------------------------------------------------- C-MSL4: msl.* plugins

MSL4_TABLE_PLUGINS = ("msl.pagemap", "msl.modules", "msl.threads", "msl.keyhints")


@pytest.fixture(scope="session")
def all_samples(samples):
    """Every ``samples/*.msl.gz`` unpacked (checksums were verified by ``samples``)."""
    paths = {}
    for packed in sorted(SAMPLES.glob("*.msl.gz")):
        target = samples["work"] / packed.name[:-3]
        if not target.exists():
            with gzip.open(packed, "rb") as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
        paths[target.name] = target
    return paths


def _memdiver_truth(path: Path) -> dict:
    """What MemDiver's reader says about ``path`` (the ground truth of C-MSL4)."""
    from memdiver.msl.enums import PageState
    from memdiver.msl.reader import MslReader

    reader = MslReader(path)
    reader.open()
    try:
        runs = []
        for region in reader.collect_regions():
            size = int(region.page_size)
            runs += [(int(region.base_addr) + iv.start_page * size, PageState(iv.state).name,
                      iv.count) for iv in region.page_intervals]
        return {"runs": runs,
                "modules": sorted({(m.base_addr, m.module_size, m.path)
                                   for m in reader.collect_modules()}),
                "threads": sorted(t.thread_id for t in reader.collect_thread_contexts()),
                "hints": len(reader.collect_key_hints()),
                "blocks": len(list(reader._iter_raw_block_headers()))}
    finally:
        reader.close()


STATE_NAMES = {"CAPTURED": "Captured", "FAILED": "Failed", "UNMAPPED": "Unmapped",
               "NOT_RESIDENT": "NotResident"}


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_MSL4_msl_plugins_equal_memdiver_reader(tree, vols, all_samples, claim):
    claim("C-MSL4", tree)
    vol = _tree(vols, tree, claim)
    checked = 0
    for name, msl in all_samples.items():
        truth = _memdiver_truth(msl)
        pagemap, _o, _r = vol.run(msl, ["msl.pagemap"])
        assert [(r["Start(V)"], r["State"], r["Pages"]) for r in pagemap] == [
            (va, STATE_NAMES[state], pages) for va, state, pages in truth["runs"]], name
        modules, _o, _r = vol.run(msl, ["msl.modules"])
        assert sorted({(r["Base"], r["Size"], r["Path"]) for r in modules}) == truth["modules"], name
        threads, _o, _r = vol.run(msl, ["msl.threads"])
        assert sorted(r["TID"] for r in threads) == truth["threads"], name
        hints, _o, _r = vol.run(msl, ["msl.keyhints"])
        assert len(hints) == truth["hints"], name
        verify, _o, _r = vol.run(msl, ["msl.verify"])
        verdict = [r for r in verify if r["Type"] == "verdict"]
        assert [r["Result"] for r in verdict] == (
            ["tampered"] if "tampered" in name else ["valid"]), (name, verdict)
        assert len([r for r in verify if r["Scope"] == "block"]) == truth["blocks"], name
        checked += 1
    assert checked == len(sorted(SAMPLES.glob("*.msl.gz"))) >= 6  # every in-repo samples/*.msl.gz
    claim.version(vol.version)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_MSL4_verify_names_the_block_after_the_tampered_region(tree, vols, all_samples, claim):
    claim("C-MSL4", tree)
    vol = _tree(vols, tree, claim)
    rows, _o, _r = vol.run(all_samples["gocryptfs_aes_tampered.msl"], ["msl.verify"])
    broken = [r for r in rows if r["Result"] == "link broken"]
    assert [(r["Type"], r["Index"]) for r in broken] == [("VAS_MAP", 14)]
    assert "block 13 (MEMORY_REGION" in broken[0]["Detail"]
    summary = {r["Type"]: r["Result"] for r in rows if r["Scope"] == "summary"}
    assert summary["hash chain"] == summary["EoC FileHash"] == "tampered"
    claim.version(vol.version)


def test_C_MSL4_encrypted_sample_verifies_with_the_key(vols, samples, claim):
    claim("C-MSL4", "stock")
    vol = _tree(vols, "stock", claim)
    encrypted = SAMPLES / samples["manifest"]["encrypted"]["file"]
    key_file = SAMPLES / samples["manifest"]["encrypted"]["key_file"]
    rows, _o, _r = vol.run(encrypted, ["msl.verify"], env={KEY_FILE_ENV: str(key_file)})
    assert [r["Result"] for r in rows if r["Type"] == "verdict"] == ["valid"]
    claim.version(vol.version)


def test_C_MSL4_bare_vol_equals_stock_vol(vols, all_samples, claim):
    claim("C-MSL4", "bare")
    bare, stock = _tree(vols, "bare", claim), _tree(vols, "stock", claim)
    python = _bare_python(bare.argv[0])
    if python:
        probe = subprocess.run([python, "-I", "-c", "import importlib.util as u; print(sorted(m for m "
                                "in ('memdiver', 'cryptography', 'blake3') if u.find_spec(m)))"],
                               capture_output=True, text=True, timeout=60)
        assert probe.stdout.strip() == "[]", "MEMDIVER_VOL3_BARE_VOL is not bare: " + probe.stdout
    for name, msl in all_samples.items():
        if "encrypted" in name:
            continue
        for plugin in MSL4_TABLE_PLUGINS:
            assert bare.run(msl, [plugin])[0] == stock.run(msl, [plugin])[0], (name, plugin)
        bare_info = {r["Variable"]: r["Value"] for r in bare.run(msl, ["msl.info"])[0]}
        stock_info = {r["Variable"]: r["Value"] for r in stock.run(msl, ["msl.info"])[0]}
        assert bare_info.pop("Integrity").startswith("not verified (the container's HashAlgo is BLAKE3")
        stock_info.pop("Integrity")
        assert bare_info == stock_info, name
        verify = bare.run(msl, ["msl.verify"])[0]
        assert [(r["Result"], "needs memdiver (BLAKE3" in r["Detail"]) for r in verify] == [
            ("not verified", True)], name
    claim.version(bare.version)


def test_C_MSL4_bare_vol_refuses_the_encrypted_sample_with_the_install_hint(vols, samples, claim):
    claim("C-MSL4", "bare")
    bare = _tree(vols, "bare", claim)
    encrypted = SAMPLES / samples["manifest"]["encrypted"]["file"]
    rows, _o, result = bare.run(encrypted, ["msl.info"], check=False)
    assert "pip install memdiver" in result.stdout + result.stderr
    assert result.returncode != 0 or not rows
    claim.version(bare.version)


@pytest.fixture(scope="session")
def fresh_plugin(samples):
    """The plugin synthesized NOW from the two in-repo slices (MemDiver library call)."""
    pytest.importorskip("volatility3")
    from memdiver.services import synthesize_vol3_plugin

    slices = [samples["manifest"]["slices"][c] for c in ("aes", "xchacha")]
    case = samples["work"] / "case"
    case.mkdir()
    result = synthesize_vol3_plugin(
        dump_paths=[str(samples["paths"][s["msl"]]) for s in slices], name="memdiver_gocryptfs",
        key_hex=[s["master_key_hex"] for s in slices], oracle_kind=ORACLE_KIND,
        oracle_sample_path=[str(SAMPLES / s["oracle_sample"]) for s in slices], case_dir=str(case))
    assert result["proven"] is True, result["verdicts"]
    assert all(s["master_key_hex"] not in json.dumps(result, default=str) for s in slices)
    return Path(result["stored"]["path"]).parent


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SYN1_synthesize_and_prove(tree, vols, samples, fresh_plugin, claim):
    claim("C-SYN1", tree)
    vol = _tree(vols, tree, claim)
    for cipher in ("aes", "xchacha"):
        entry, msl = _slice(samples, cipher)
        rows = _plugin_rows(vol, msl, SAMPLES / entry["oracle_sample"], plugin_dirs=(PLUGINS, fresh_plugin))
        assert _proven(rows) == _expected_rows(entry), cipher
    claim.version(vol.version)


def _bare_python(vol_path: str):
    """The interpreter of a console-script ``vol`` (its shebang), else None."""
    first = Path(vol_path).read_bytes()[:256].split(b"\n", 1)[0]
    if first.startswith(b"#!"):
        python = first[2:].decode().strip().split()[0]
        return python if Path(python).is_file() else None
    return None


def test_C_SYN2_committed_plugin_on_bare_stock_vol(vols, samples, claim):
    claim("C-SYN2", "bare")
    vol = _tree(vols, "bare", claim)
    python = _bare_python(vol.argv[0])
    if python:
        probe = subprocess.run([python, "-I", "-c", "import importlib.util as u; print(sorted(m for m in "
                                "('memdiver', 'cryptography', 'Crypto') if u.find_spec(m)))"],
                               capture_output=True, text=True, timeout=60)
        assert probe.stdout.strip() == "[]", "MEMDIVER_VOL3_BARE_VOL is not bare: " + probe.stdout
    for cipher in ("aes", "xchacha"):
        entry, msl = _slice(samples, cipher)
        rows = _plugin_rows(vol, msl, SAMPLES / entry["oracle_sample"])
        # Scope msl:<pid> needs the slim pure-Python .msl reader in vol3plugins/ (no MemDiver).
        assert _proven(rows) == _expected_rows(entry), (cipher, rows)
    claim.version(vol.version)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_IMP1_import_hygiene(tree, vols, claim):
    claim("C-IMP1", tree)
    vol = _tree(vols, tree, claim)
    from tests.test_vol3plugins_import_rules import _DRIVER, _plugin_files, import_violations

    files = _plugin_files() + [SAMPLE_PLUGINS / "memdiver_gocryptfs.py"]
    problems = {str(p.relative_to(REPO)): import_violations(p.read_text(encoding="utf-8"),
                                                            p if PLUGINS in p.parents else None)
                for p in files}
    assert {k: v for k, v in problems.items() if v} == {}
    times = []
    for _ in range(3):
        start = time.perf_counter()
        proc = subprocess.run(vol.argv + ["-p", str(PLUGINS), "-h"], capture_output=True, text=True, timeout=120)
        times.append(time.perf_counter() - start)
        assert proc.returncode == 0, proc.stderr[-2000:]
    assert min(times) < 1.5, "vol -p vol3plugins -h best-of-3 %.2fs" % min(times)
    for plugin in ("linux.dmcrypt", "linux.wireguard", "linux.keyring", "linux.fscrypt", "linux.ecryptfs",
                   "msl.info"):
        assert plugin in proc.stdout, plugin
    match = BANNER.search(proc.stdout + proc.stderr)
    vol.version = match.group(1) if match else vol.version
    claim.version(vol.version)
    driver = subprocess.run([sys.executable, "-I", "-c", _DRIVER, str(PLUGINS)], capture_output=True,
                            text=True, timeout=300, cwd="/")
    assert driver.returncode == 0 and driver.stdout.strip().splitlines()[-1] == "[]", driver.stdout[-2000:]


# --------------------------------------------------------------------------- acquired captures (gated)


def _capture(stem: str):
    files = {ext: CORPUS / (stem + ext) for ext in (".lime", ".isf.json", ".secrets.json")}
    if not all(p.is_file() for p in files.values()):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture %s not present" % stem)
    return files, json.loads(files[".secrets.json"].read_text())


@pytest.fixture(scope="session")
def symbol_dirs(tmp_path_factory):
    made = {}

    def get(stem: str) -> Path:
        if stem not in made:
            root = tmp_path_factory.mktemp("sym")
            (root / "linux").mkdir()
            (root / "linux" / (stem + ".json")).symlink_to(CORPUS / (stem + ".isf.json"))
            made[stem] = root
        return made[stem]

    return get


def _on_capture(vols, tree, claim, stem, symbol_dirs, args, env=None):
    vol = _tree(vols, tree, claim)
    files, truth = _capture(stem)
    rows, out, result = vol.run(files[".lime"], args, symbols=symbol_dirs(stem), env=env)
    claim.version(vol.version)
    return rows, out, result, truth


def _dmcrypt(vols, tree, claim, symbol_dirs, stem=STEM_4LEVEL, env=None):
    return _on_capture(vols, tree, claim, stem, symbol_dirs,
                       ["linux.dmcrypt", "--export", "dmsetup", "--verbose"], env)


def _assert_dmsetup(out: Path, devices: dict) -> None:
    lines = (out / "dmcrypt.dmsetup.txt").read_text().splitlines()
    assert sorted(lines) == sorted("%s: %s" % (n, d["dm_table_showkeys"]) for n, d in devices.items())


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_DM1_dmcrypt_keys_byte_exact(tree, vols, symbol_dirs, claim):
    claim("C-DM1", tree)
    rows, out, _res, truth = _dmcrypt(vols, tree, claim, symbol_dirs)
    devices = {d["name"]: d for d in truth["dmcrypt"]}
    by_name = {r["Name"]: r for r in rows}
    assert set(by_name) == set(devices) and len(devices) >= 3
    assert all(by_name[n]["Key"] == d["volume_key_hex"] for n, d in devices.items())
    _assert_dmsetup(out, devices)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_DM2_dmcrypt_oracles(tree, vols, symbol_dirs, claim):
    claim("C-DM2", tree)
    rows, _out, _res, truth = _dmcrypt(vols, tree, claim, symbol_dirs)
    by_name = {r["Name"]: r for r in rows}
    for device in truth["dmcrypt"]:
        row = by_name[device["name"]]
        expected = (r"O1\+O2(\+O3)?:luks-digest(\+[a-z0-9-]+)?" if device["type"].startswith("luks")
                    else r"O1\+O3:(pagecache-pair|vfat|ext4|xfs|ntfs|btrfs)")
        assert row["Status"] == "proven" and re.fullmatch(expected, row["Oracle"]), (device["name"], row["Oracle"])


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_DM3_offsets_from_in_memory_btf(tree, vols, symbol_dirs, claim):
    claim("C-DM3", tree)
    rows, out, result, truth = _dmcrypt(vols, tree, claim, symbol_dirs, env={HIDE_TABLE_ENV: "1"})
    assert "TEST ONLY" in result.stderr  # the table really was hidden
    devices = {d["name"]: d for d in truth["dmcrypt"]}
    assert {r["Name"]: r["Key"] for r in rows} == {n: d["volume_key_hex"] for n, d in devices.items()}
    _assert_dmsetup(out, devices)


def _wireguard(vols, tree, claim, symbol_dirs, mode: str):
    return _on_capture(vols, tree, claim, STEM_4LEVEL, symbol_dirs, ["linux.wireguard", "--export", mode])


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WG1_wireguard_identities_and_peers(tree, vols, symbol_dirs, claim):
    claim("C-WG1", tree)
    _rows, out, result, truth = _wireguard(vols, tree, claim, symbol_dirs, "json")
    assert "guessed WireGuard offsets" not in result.stderr
    report = json.loads((out / "wireguard.json").read_text())
    assert len(report) == len(truth["wireguard"]) >= 2
    for interface in truth["wireguard"]:
        [got] = [r for r in report if r["public_key"] == interface["public_key_b64"]]
        assert got["private_key"] == interface["private_key_b64"] and got["status"] == "proven"
        assert got["listen_port"] == interface["listen_port"]
        for expected in interface["peers"]:
            [peer] = [p for p in got["peers"] if p["public_key"] == expected["public_key_b64"]]
            assert peer["status"] == "proven" and peer["checks"]["O_dh"] == "pass"
            assert (peer["preshared_key"], peer["endpoint"], ",".join(peer["allowed_ips"])) == (
                expected["preshared_key_b64"], expected["endpoint"], expected["allowed_ips"])


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WG2_wireguard_handshake_state(tree, vols, symbol_dirs, claim):
    claim("C-WG2", tree)
    rows, out, _res, truth = _wireguard(vols, tree, claim, symbol_dirs, "json")
    report = json.loads((out / "wireguard.json").read_text())
    in_flight = [(i, p) for i in truth["wireguard"] for p in i["peers"] if p["latest_handshake_unix"] == 0]
    assert in_flight
    for interface, expected in in_flight:
        [got] = [r for r in report if r["public_key"] == interface["public_key_b64"]]
        [peer] = [p for p in got["peers"] if p["public_key"] == expected["public_key_b64"]]
        assert peer["handshake_state"] == "created_initiation" and peer["checks"]["O_ck"] == "pass"
    psk_rows = [r for r in rows if r["Slot"] == "handshake" and r["PSK"] != "(none)"]
    assert psk_rows and all("PSK:bound-to-proven-peer" in r["Verified"] for r in psk_rows)
    transport = [r for r in rows if r["Slot"] in ("current", "previous", "next")]
    assert transport and all(r["Status"] == "unverified" for r in transport)


KEYLOG_LINE = re.compile(r"^(LOCAL_STATIC_PRIVATE_KEY|REMOTE_STATIC_PUBLIC_KEY|LOCAL_EPHEMERAL_PRIVATE_KEY"
                         r"|PRESHARED_KEY) = ([A-Za-z0-9+/]{43}=)$")


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WG3_wireguard_keylog_export(tree, vols, symbol_dirs, claim):
    claim("C-WG3", tree)
    _rows, out, _res, truth = _wireguard(vols, tree, claim, symbol_dirs, "keylog")
    lines = [line for line in (out / "wireguard.keylog").read_text().splitlines()
             if line and not line.startswith("#")]
    parsed = [KEYLOG_LINE.match(line) for line in lines]
    assert lines and all(parsed), [line for line, m in zip(lines, parsed) if not m]
    kinds = [m.group(1) for m in parsed]
    for index, kind in enumerate(kinds):
        if kind == "PRESHARED_KEY":
            assert index and kinds[index - 1] == "LOCAL_EPHEMERAL_PRIVATE_KEY"
    statics = {m.group(2) for m in parsed if m.group(1) == "LOCAL_STATIC_PRIVATE_KEY"}
    assert statics == {i["private_key_b64"] for i in truth["wireguard"]}
    peers = {p["public_key_b64"] for i in truth["wireguard"] for p in i["peers"]}
    assert {m.group(2) for m in parsed if m.group(1) == "REMOTE_STATIC_PUBLIC_KEY"} <= peers
    for entry in json.loads((out / "wireguard.wg-transport.json").read_text()).get("keypairs", []):
        assert entry["send_key"] is None and entry["recv_key"] is None


def _proc_keys(text: str) -> dict:
    rows = {}
    for line in text.splitlines():
        fields = line.split(None, 8)
        rows[fields[0]] = (fields[7], fields[8].split(":")[0] if fields[7] != "asymmetri" else fields[8])
    return rows


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_KR1_keyring(tree, vols, symbol_dirs, claim):
    claim("C-KR1", tree)
    tarball = CORPUS / (STEM_4LEVEL + ".secrets.tar.gz")
    if not tarball.is_file():
        pytest.skip("MEMDIVER_SECRETS_CORPUS ground-truth tarball not present")
    rows, out, _res, truth = _on_capture(vols, tree, claim, STEM_4LEVEL, symbol_dirs,
                                         ["linux.keyring", "--export", "keyctl"])
    with tarfile.open(tarball) as archive:
        expected = _proc_keys(archive.extractfile("artefacts/proc_keys.txt").read().decode())
    mine = _proc_keys((out / "keyring.proc_keys.txt").read_text())
    assert len([s for s in expected if s not in mine]) <= 2
    assert all(mine[s] == expected[s] for s in expected if s in mine)
    ecryptfs = truth["ecryptfs"][0]
    tok = [r for r in rows if r["Description"] == ecryptfs["fekek_signature"]]
    assert len(tok) == 1 and tok[0]["Status"] == "proven" and tok[0]["Payload"].startswith(ecryptfs["fekek_hex"][:64])


def _fscrypt_v1_descriptor(raw_hex: str) -> str:
    """``SHA-512(SHA-512(raw))[:8]`` with hashlib (independent of the plugins)."""
    return hashlib.sha512(hashlib.sha512(bytes.fromhex(raw_hex)).digest()).digest()[:8].hex()


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_KR2_keyring_cryptsetup_and_fscrypt_logon_keys(tree, vols, symbol_dirs, claim):
    claim("C-KR2", tree)
    rows, _out, _res, truth = _on_capture(vols, tree, claim, STEM_V2B, symbol_dirs,
                                          ["linux.keyring", "--verbose"])
    [luks2] = [d for d in truth["dmcrypt"] if d.get("keyring_vk")]
    vk = luks2["keyring_vk"]
    assert vk["payload_matches_volume_key"] is True
    [row] = [r for r in rows if r["Description"] == vk["description"]]
    uuid = vk["description"][len("cryptsetup:"):-len("-d0")]
    assert (row["Type"], row["Status"]) == (vk["type"], "proven")
    assert row["Semantics"] == "dmcrypt-volume-key uuid=%s seg=0 512bit [dmcrypt-cross]" % uuid
    assert row["Payload"] == luks2["volume_key_hex"]
    dm_rows, _o, _r, _t = _dmcrypt(vols, tree, claim, symbol_dirs, stem=STEM_V2B)
    [dm_row] = [r for r in dm_rows if r["Name"] == luks2["name"]]
    assert (dm_row["Status"], dm_row["Key"]) == ("proven", row["Payload"])
    v1 = _fscrypt_entry(truth["fscrypt"], "v1")
    logon = v1["legacy_logon_key"]
    [frow] = [r for r in rows if r["Description"] == logon["description"]]
    assert logon["description"] == "fscrypt:" + v1["key_ref_hex"] == "fscrypt:" + _fscrypt_v1_descriptor(
        v1["master_key_hex"])
    assert (frow["Type"], frow["Status"], frow["Payload"]) == ("logon", "proven", v1["master_key_hex"])
    assert frow["Semantics"] == "fscrypt-v1-master desc=%s mode=1 size=64 [fscrypt-desc]" % v1["key_ref_hex"]


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_FS4_fscrypt_v1_descriptor_cross_check(tree, vols, symbol_dirs, claim):
    claim("C-FS4", tree)
    rows, _out, _res, truth = _on_capture(vols, tree, claim, STEM_V2B, symbol_dirs,
                                          ["linux.fscrypt", "--export", "json"])
    entry = _fscrypt_entry(truth["fscrypt"], "v1")
    assert entry["descriptor_derived"] is True
    assert entry["key_ref_hex"] == _fscrypt_v1_descriptor(entry["master_key_hex"])
    row = {r["KeyRef"]: r for r in rows}[entry["key_ref_hex"]]
    assert (row["KeyHex"], row["Proven"]) == (entry["master_key_hex"], "oracle:descriptor+per-file-schedule")


def _fscrypt(vols, tree, claim, symbol_dirs):
    rows, out, _res, truth = _on_capture(vols, tree, claim, STEM_4LEVEL, symbol_dirs,
                                         ["linux.fscrypt", "--export", "json"])
    report = {e["key_ref_hex"]: e for e in json.loads((out / "fscrypt.json").read_text())}
    return {r["KeyRef"]: r for r in rows}, report, truth["fscrypt"]


def _fscrypt_entry(truth: list, version: str) -> dict:
    [entry] = [e for e in truth if e["policy_version"] == version]
    return entry


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_FS1_fscrypt_v1_master_key(tree, vols, symbol_dirs, claim):
    claim("C-FS1", tree)
    rows, _report, truth = _fscrypt(vols, tree, claim, symbol_dirs)
    entry = _fscrypt_entry(truth, "v1")
    row = rows[entry["key_ref_hex"]]
    assert (row["KeyHex"], row["Proven"]) == (entry["master_key_hex"], "oracle:per-file-schedule")


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_FS2_fscrypt_v2_identifier(tree, vols, symbol_dirs, claim):
    claim("C-FS2", tree)
    from memdiver.vol3plugins.linux.secrets import hkdf_midstate

    rows, report, truth = _fscrypt(vols, tree, claim, symbol_dirs)
    entry = _fscrypt_entry(truth, "v2")
    ipad, opad = hkdf_midstate.fscrypt_v2_hkdf_midstates(bytes.fromhex(entry["master_key_hex"]))
    midstates = report[entry["key_ref_hex"]]["hkdf_prk_midstates"]
    import struct

    assert midstates["ipad_sha512_state_hex"] == struct.pack(">8Q", *ipad).hex()
    assert midstates["opad_sha512_state_hex"] == struct.pack(">8Q", *opad).hex()
    assert rows[entry["key_ref_hex"]]["Proven"] == "oracle:identifier+per-file-schedule"


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_FS3_fscrypt_per_file_proof_complete(tree, vols, symbol_dirs, claim):
    claim("C-FS3", tree)
    rows, _report, truth = _fscrypt(vols, tree, claim, symbol_dirs)
    assert {e["policy_version"] for e in truth} == {"v1", "v2"}
    for entry in truth:
        row = rows[entry["key_ref_hex"]]
        assert (row["Policy"], row["Device"], row["FsType"], row["Offsets"]) == (
            entry["policy_version"], Path(entry["loop_device"]).name, "ext4", "isf")
        assert row["Modes"] == "%s/%s %s" % (entry["contents_mode"], entry["filenames_mode"], entry["flags"])
        matched, checked = map(int, row["Inodes"].split("/"))
        assert checked > 0 and matched == checked


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_EC1_ecryptfs(tree, vols, symbol_dirs, claim):
    claim("C-EC1", tree)
    rows, out, _res, truth = _on_capture(vols, tree, claim, STEM_4LEVEL, symbol_dirs,
                                         ["linux.ecryptfs", "--export", "json"])
    expected = truth["ecryptfs"][0]
    assert rows and all(r["Proven"].startswith("oracle:ecryptfs-root-iv+tfm-schedule") for r in rows)
    assert all((r["Mount"], r["Source"], r["Offsets"]) == (expected["mountpoint"], expected["lower_dir"], "isf")
               for r in rows)
    assert all(r["KeySigs"] == expected["fekek_signature"] and "keyring proven" in r["MountAuthTok"]
               and r["MountAuthTok"].startswith(expected["fekek_signature"] + " fekek") for r in rows)
    assert len(json.loads((out / "ecryptfs.json").read_text())["files"]) == len(rows)


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB from ``cryptography`` (independent of the plugins' own AES)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # nosec B305 - the eCryptfs key wrap is ECB
    return decryptor.update(data) + decryptor.finalize()


def _ecryptfs_wrapped_fek(header: bytes) -> bytes:
    """The encrypted FEK of the first tag-3 packet of an eCryptfs lower-file header (keystore.c)."""
    assert int.from_bytes(header[8:12], "big") ^ int.from_bytes(header[12:16], "big") == 0x3C81B7F5
    pos = 26  # size(8) + marker(8) + flags(4) + header extent size(4) + extents at front(2)
    assert header[pos] == 0x8C, "no tag-3 packet"
    length, pos = header[pos + 1], pos + 2
    if length >= 192:
        length, pos = (length - 192) * 256 + header[pos] + 192, pos + 1
    return header[pos + 13:pos + length]  # version, cipher, s2k, hash, salt[8], count


def _stock_lower_header(vols, tree, claim, stem, symbol_dirs, inode_address: int) -> bytes:
    """Page 0 of a lower inode as STOCK ``InodePages --dump`` writes it (memoised per vol tree)."""
    files, _truth = _capture(stem)
    vol = vols.get("stock") or _tree(vols, tree, claim)
    _rows, out, _res = vol.run(files[".lime"], ["linux.pagecache.InodePages", "--inode", str(inode_address),
                                                "--dump"], symbols=symbol_dirs(stem))
    (dumped,) = [p for p in out.glob("inode_*.dmp")
                 if (int(p.stem[6:], 16) ^ inode_address) & ((1 << 47) - 1) == 0]
    return dumped.read_bytes()[:4096]


@pytest.mark.parametrize("stem", [STEM_4LEVEL, STEM_LA57], ids=["4level", "la57"])
@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_EC2_ecryptfs_tag3_and_exports(tree, stem, vols, symbol_dirs, claim):
    claim("C-EC2", tree)
    rows, out, _res, truth = _on_capture(vols, tree, claim, stem, symbol_dirs, ["linux.ecryptfs", "--export", "fek"])
    expected = truth["ecryptfs"][0]
    assert rows and all(r["Proven"] == "oracle:ecryptfs-root-iv+tfm-schedule+ecryptfs-tag3" for r in rows)
    _rows, fekek_out, _res, _truth = _on_capture(vols, tree, claim, stem, symbol_dirs,
                                                 ["linux.ecryptfs", "--export", "fekek"])
    assert (fekek_out / "ecryptfs_fekek.txt").read_text() == "%s %s\n" % (
        expected["fekek_signature"], expected["fekek_hex"])
    lines = (out / "ecryptfs_fek.csv").read_text().splitlines()
    assert lines[0] == "lower_path,inode,cipher,fek_hex" and len(lines) == len(rows) + 1
    exported = {line.rsplit(",", 3)[0]: line.rsplit(",", 3)[1:] for line in lines[1:]}
    fekek = bytes.fromhex(expected["fekek_hex"])
    for row in rows:
        assert exported[row["LowerPath"]] == [str(row["LowerInode"]), expected["cipher"], row["KeyHex"]]
        assert row["LowerPath"].startswith(expected["lower_dir"] + "/")
        header = _stock_lower_header(vols, tree, claim, stem, symbol_dirs, row["LowerInodeAddr"])
        size = expected["key_bytes"]
        assert aes_ecb_decrypt(fekek[:size], _ecryptfs_wrapped_fek(header))[:size].hex() == row["KeyHex"]


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_LA57_five_level_paging(tree, vols, symbol_dirs, claim):
    claim("C-LA57", tree)
    rows, _out, _res, truth = _on_capture(vols, tree, claim, STEM_LA57, symbol_dirs, ["linux.pslist"])
    assert len(rows) >= 100
    daemon_pids = {int(pid) for pid in str(truth["gocryptfs"][0]["daemon_pids"]).replace(",", " ").split()}
    assert daemon_pids and daemon_pids <= {r["PID"] for r in rows}
    dm_rows, out, _res, _truth = _dmcrypt(vols, tree, claim, symbol_dirs, stem=STEM_LA57)
    devices = {d["name"]: d for d in truth["dmcrypt"]}
    assert {r["Name"]: (r["Key"], r["Status"]) for r in dm_rows} == {
        n: (d["volume_key_hex"], "proven") for n, d in devices.items()}
    _assert_dmsetup(out, devices)


SSH_CORPUS = Path(os.environ.get("MEMDIVER_SSH_CORPUS", "") or "/nonexistent")
SSH_PLUGIN = "memdiver.ssh.SSHKeys"
#: Implementations that drop K after NEWKEYS (Paramiko ``_parse_newkeys``: ``self.K = None``).
K_DROPPED = ("paramiko",)


def _ssh_keys(rows, pid, tier):
    return {r["Direction"]: r["KeyHex"] for r in rows
            if r["PID"] == pid and r["Tier"] == tier and r["Kind"].startswith("key")}


@pytest.mark.parametrize("stem", [STEM_4LEVEL, STEM_LA57], ids=["4level", "la57"])
@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SSH1_openssh_and_dropbear_structural(tree, stem, vols, symbol_dirs, claim):
    claim("C-SSH1", tree)
    rows, _out, _res, truth = _on_capture(vols, tree, claim, stem, symbol_dirs, [SSH_PLUGIN])
    sessions = {s["server"]: s for s in truth["ssh"]}
    openssh, dropbear = sessions["openssh"], sessions["dropbear"]
    client = _ssh_keys(rows, openssh["client_pid"], "B")
    assert sorted(client) == ["c2s", "s2c"] and all(len(k) == 128 for k in client.values())
    servers = {r["PID"] for r in rows if r["Process"] == "sshd" and _ssh_keys(rows, r["PID"], "B") == client}
    assert servers, "no sshd process holds the client's keys"
    cipher = openssh["cipher_c2s"].split()[0]
    assert {r["Cipher"] for r in rows if r["PID"] == openssh["client_pid"]} == {cipher}
    db_client = _ssh_keys(rows, dropbear["client_pid"], "B")
    db_server = _ssh_keys(rows, int(dropbear["server_pids"]), "C")
    assert sorted(db_client) == ["c2s", "s2c"] and db_server == db_client
    ssh_pids = {openssh["client_pid"], dropbear["client_pid"], int(dropbear["server_pids"])} | servers
    assert all(r["Proven"] == "unverified" for r in rows if r["PID"] in ssh_pids)
    by_pid, _o, _r = _tree(vols, tree, claim).run(
        _capture(stem)[0][".lime"], [SSH_PLUGIN, "--pid", str(openssh["client_pid"])],
        symbols=symbol_dirs(stem))
    assert _ssh_keys(by_pid, openssh["client_pid"], "B") == client


def _proven_ssh_letters(rows, keys):
    """``{letter}`` of proven rows; asserts each proven key equals ``keys[letter]``."""
    letters = set()
    for row in rows:
        if row["Proven"] != "oracle:ssh-kdf-consistency":
            continue
        assert row["Tier"] == "A"
        letter = row["Kind"].split("/")[-1]
        # exact: same bytes and the length the implementation used (not a prefix)
        assert row["KeyHex"] == keys[letter].lower() and row["Length"] * 2 == len(keys[letter]), letter
        letters.add(letter)
    return letters


@pytest.mark.parametrize("impl", ["libssh", "wolfssh"])
@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SSH1_tier_a_on_in_repo_samples(tree, impl, vols, samples, claim):
    claim("C-SSH1", tree)
    vol = _tree(vols, tree, claim)
    entry = samples["manifest"]["ssh"][impl]
    target = samples["work"] / entry["msl"]
    if not target.exists():
        with gzip.open(SAMPLES / entry["file"], "rb") as packed, open(target, "wb") as out:
            shutil.copyfileobj(packed, out, 1 << 20)
    assert _sha256(target) == entry["msl_sha256"]
    rows, _out, _res = vol.run(target, [SSH_PLUGIN])
    claim.version(vol.version)
    assert "".join(sorted(_proven_ssh_letters(rows, entry["keys"]))) == entry["expected_letters"]
    assert {r["Scope"] for r in rows} == {"msl:%d" % entry["pid"]}


def _ssh_sessions():
    return sorted(p.parent for p in SSH_CORPUS.glob("*/gt.json")) if SSH_CORPUS.is_dir() else []


@pytest.mark.parametrize("session", _ssh_sessions() or [None], ids=lambda p: p.name if p else "no-corpus")
@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SSH1_tier_a_on_msl_slices(tree, session, vols, claim):
    claim("C-SSH1", tree)
    vol = _tree(vols, tree, claim)
    if session is None:
        pytest.skip("MEMDIVER_SSH_CORPUS not set or holds no <session>/gt.json")
    truth = json.loads((session / "gt.json").read_text())
    for proc in truth if isinstance(truth, list) else [truth]:
        rows, _out, _res = vol.run(session / proc.get("msl_small", proc["msl"]), [SSH_PLUGIN])
        claim.version(vol.version)
        if proc["implementation"] in K_DROPPED:   # K is gone: a proof would be a false claim
            assert not [r for r in rows if r["Proven"] == "oracle:ssh-kdf-consistency"]
            continue
        assert len(_proven_ssh_letters(rows, proc["keys"])) >= 2, (session.name, proc["role"])


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SSH2_x86_full_image_libssh_tier_a_by_pid(tree, vols, symbol_dirs, claim):
    claim("C-SSH2", tree)
    vol = _tree(vols, tree, claim)
    files, truth = _capture(STEM_V2B)
    session = truth["ssh_tier_a"][0]
    assert session["implementation"] == "libssh"
    pid = session["pid"]
    rows, _out, _res = vol.run(files[".lime"], [SSH_PLUGIN, "--pid", str(pid)],
                               symbols=symbol_dirs(STEM_V2B))
    claim.version(vol.version)
    assert "".join(sorted(_proven_ssh_letters(rows, session["keys"]))) == "ABCDEF"
    proven = [r for r in rows if r["Proven"] == "oracle:ssh-kdf-consistency"]
    assert {r["PID"] for r in proven} == {pid} and {r["Scope"] for r in proven} == {"process:%d" % pid}
    named = {r["Kind"].split("/")[-1]: r["Cipher"] for r in proven}
    assert named == {"A": session["cipher_c2s"], "B": session["cipher_s2c"],
                     "C": session["cipher_c2s"], "D": session["cipher_s2c"],
                     "E": session["mac_c2s"], "F": session["mac_s2c"]}
    assert all(r["Detail"].endswith("lengths: negotiated(libssh)") for r in proven)
    peer, _out, _res = vol.run(files[".lime"], [SSH_PLUGIN, "--pid", str(session["server_pid"])],
                               symbols=symbol_dirs(STEM_V2B))
    assert session["server_implementation"] in K_DROPPED
    assert not [r for r in peer if r["Proven"] == "oracle:ssh-kdf-consistency"]


WG_GO_PLUGIN = "memdiver.wireguard_go.WireGuardGo"
WG_GO_KEY_OF = {"static-private": "static_private", "peer-public": "peer_public",
                "ephemeral-private": "ephemeral_private", "send": "send", "receive": "receive"}


def _wg_go_by_kind(rows) -> dict:
    """``{kind: [(key hex, Proven, Address)]}`` of a WireGuardGo table."""
    found = {}
    for row in rows:
        found.setdefault(row["Kind"], []).append(
            (base64.b64decode(row["Key"]).hex(), row["Proven"], row["Address"]))
    return found


def _wg_go_keylog(out: Path) -> list:
    lines = [line for line in (out / "wireguard_go.keylog").read_text().splitlines()
             if line and not line.startswith("#")]
    parsed = [KEYLOG_LINE.match(line) for line in lines]
    assert lines and all(parsed), [line for line, m in zip(lines, parsed) if not m]
    return [(m.group(1), base64.b64decode(m.group(2)).hex()) for m in parsed]


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WGGO1_in_repo_sample(tree, vols, samples, claim):
    claim("C-WGGO1", tree)
    vol = _tree(vols, tree, claim)
    entry = samples["manifest"]["wireguard_go"]
    target = samples["work"] / entry["msl"]
    if not target.exists():
        with gzip.open(SAMPLES / entry["file"], "rb") as packed, open(target, "wb") as out:
            shutil.copyfileobj(packed, out, 1 << 20)
    assert _sha256(target) == entry["msl_sha256"]
    rows, _out, _res = vol.run(target, [WG_GO_PLUGIN])
    claim.version(vol.version)
    found = _wg_go_by_kind(rows)
    assert sorted(found) == sorted(entry["expected"])
    for kind, expected in entry["expected"].items():
        assert found[kind] == [(entry["keys"][WG_GO_KEY_OF[kind]], expected["proven"],
                                int(expected["addresses"][0], 16))], kind
    assert {r["Scope"] for r in rows} == {"msl:%d" % entry["pid"]}
    _rows, out, _res = vol.run(target, [WG_GO_PLUGIN, "--export", "keylog"])
    keylog = _wg_go_keylog(out)
    assert ("LOCAL_STATIC_PRIVATE_KEY", entry["keys"]["static_private"]) in keylog
    assert ("REMOTE_STATIC_PUBLIC_KEY", entry["keys"]["peer_public"]) in keylog
    assert ("LOCAL_EPHEMERAL_PRIVATE_KEY", entry["keys"]["ephemeral_private"]) in keylog
    transport = json.loads((out / "wireguard_go.wg-transport.json").read_text())["keypairs"]
    assert transport and all(e["send_key"] is None and e["recv_key"] is None for e in transport)


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WGGO2_preshared_key_proven_on_real_data(tree, vols, samples, claim):
    claim("C-WGGO2", tree)
    vol = _tree(vols, tree, claim)
    entry = samples["manifest"]["wireguard_go_psk"]
    target = samples["work"] / entry["msl"]
    if not target.exists():
        with gzip.open(SAMPLES / entry["file"], "rb") as packed, open(target, "wb") as out:
            shutil.copyfileobj(packed, out, 1 << 20)
    assert _sha256(target) == entry["msl_sha256"]
    rows, _out, _res = vol.run(target, [WG_GO_PLUGIN])
    claim.version(vol.version)
    found = _wg_go_by_kind(rows)
    key_of = dict(WG_GO_KEY_OF, preshared="preshared")
    assert sorted(found) == sorted(entry["expected"]) == sorted(
        ["static-private", "peer-public", "ephemeral-private", "preshared"])
    for kind, expected in entry["expected"].items():
        assert found[kind] == [(entry["keys"][key_of[kind]], expected["proven"],
                                int(expected["addresses"][0], 16))], kind
    assert found["preshared"][0][1] == found["ephemeral-private"][0][1] == "oracle:noise-chaining-key"
    _rows, out, _res = vol.run(target, [WG_GO_PLUGIN, "--export", "keylog"])
    keylog = _wg_go_keylog(out)
    psk_line = keylog.index(("PRESHARED_KEY", entry["keys"]["preshared"]))
    assert keylog[psk_line - 1] == ("LOCAL_EPHEMERAL_PRIVATE_KEY", entry["keys"]["ephemeral_private"])


def _wg_go_sessions():
    from tests import _wg_go_corpus

    return _wg_go_corpus.sessions()


@pytest.fixture(scope="session")
def wg_go_slices(tmp_path_factory):
    """``(run, role) -> .msl`` of the run's ``post_active`` dump, converted once per session."""
    from tests import _wg_go_corpus

    work, made = tmp_path_factory.mktemp("wg-go"), {}

    def get(run: Path, role: str) -> Path:
        if (run, role) not in made:
            (dump,) = [d for d in _wg_go_corpus.dumps(run, role)
                       if _wg_go_corpus.phase(d) == "post_active"]
            out = work / ("%s_%s.msl" % (run.name, role))
            _wg_go_corpus.import_dump(dump, out, _wg_go_corpus.pid(run, role))
            made[(run, role)] = out
        return made[(run, role)]

    return get


@pytest.mark.parametrize("session", _wg_go_sessions() or [None],
                         ids=lambda s: "%s-%s" % (s[0].name, s[1]) if s else "no-corpus")
@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_WGGO1_static_key_proven_on_every_archive_run(tree, session, vols, wg_go_slices, claim):
    claim("C-WGGO1", tree)
    vol = _tree(vols, tree, claim)
    if session is None:
        pytest.skip("MEMDIVER_WG_GO_CORPUS not set or holds no wireguard-go run")
    from tests import _wg_go_corpus

    run, role = session
    truth = _wg_go_corpus.ground_truth(run, role)
    rows, _out, _res = vol.run(wg_go_slices(run, role), [WG_GO_PLUGIN])
    claim.version(vol.version)
    found = _wg_go_by_kind(rows)
    assert [k for k, p, _a in found["static-private"] if p == "oracle:x25519-pubkey"] == [
        truth["static_private"].hex()]
    assert [k for k, p, _a in found["peer-public"] if p == "oracle:x25519-dh-consistency"] == [
        truth["peer_public"].hex()]
    assert {r["Locator"] for r in rows if r["Kind"] == "peer-public"} == {"device_backpointer"}
    assert not [r for r in rows if r["Proven"] == "rejected"]
    transport = found.get("send", []) + found.get("receive", [])
    assert transport and all(p == "unverified" and bytes.fromhex(k) in truth["transport"]
                             for k, p, _a in transport)


def test_keylog_grammar_checker_rejects_bad_lines():
    """Self-test of the C-WG3 checker (no vol needed)."""
    good = "LOCAL_STATIC_PRIVATE_KEY = " + base64.b64encode(bytes(32)).decode()
    assert KEYLOG_LINE.match(good)
    assert not KEYLOG_LINE.match(good.replace(" = ", "="))
    assert not KEYLOG_LINE.match("TRANSPORT_KEY = " + base64.b64encode(bytes(32)).decode())
    assert not KEYLOG_LINE.match("PRESHARED_KEY = " + base64.b64encode(bytes(31)).decode())


# --------------------------------------------------------------------------- C-MOUNT1 (Docker)

MOUNT_PROOF = REPO / "tools" / "vol3_capture" / "mount_proof.sh"
MOUNT_PROOF_TIMEOUT_S = 3600
MOUNT_REQUIRED = {(t, "dmsetup") for t in ("luks1", "luks2", "veracrypt")} | {
    (t, "cryptsetup-script") for t in ("luks1", "luks2")}
MOUNT_ALL_TARGETS = {"luks1", "luks2", "veracrypt", "fscrypt_v1", "fscrypt_v2", "ecryptfs", "gocryptfs"}


def _docker_works() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def test_C_MOUNT1_recovered_keys_open_the_real_containers(vols, claim, tmp_path):
    claim("C-MOUNT1", "stock")
    vol = _tree(vols, "stock", claim)
    stem = CORPUS / STEM_V2B
    if not all((CORPUS / (STEM_V2B + ext)).is_file()
               for ext in (".lime", ".isf.json", ".ps_at_dump.txt", ".containers.tar")):
        pytest.skip("MEMDIVER_SECRETS_CORPUS capture v2b %s (with containers.tar) not present" % STEM_V2B)
    if len(vol.argv) != 1:
        pytest.skip("mount_proof.sh needs a single vol executable, not %r" % vol.argv)
    if not _docker_works():
        pytest.skip("docker info failed (no Docker daemon)")
    env = dict(os.environ, MEMDIVER_VOL3_VOL=vol.argv[0], PATH=os.pathsep.join(
        [str(Path(sys.executable).parent), os.environ.get("PATH", "")]))
    for name in SCRUBBED_ENV:
        env.pop(name, None)
    try:
        proc = subprocess.run(["bash", str(MOUNT_PROOF), "--stem", str(stem), "--work", str(tmp_path)],
                              capture_output=True, text=True, timeout=MOUNT_PROOF_TIMEOUT_S, env=env)
    finally:   # ~180 MB of extracted containers; keep the plugin outputs and results
        shutil.rmtree(tmp_path / "containers", ignore_errors=True)
        shutil.rmtree(tmp_path / "cache", ignore_errors=True)
    banner = BANNER.search((tmp_path / "plugins" / "dm_dmsetup" / "stderr.txt").read_text()
                           if (tmp_path / "plugins" / "dm_dmsetup" / "stderr.txt").is_file() else "")
    claim.version(banner.group(1) if banner else vol.version)
    assert proc.returncode == 0 and "MOUNT_PROOF_EXIT=0" in proc.stdout, (proc.stdout + proc.stderr)[-4000:]
    rows = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert rows and all(r["expected"] > 0 and r["matched"] == r["expected"] for r in rows), rows
    done = {(r["target"], r["method"]) for r in rows}
    assert MOUNT_REQUIRED <= done, sorted(MOUNT_REQUIRED - done)
    assert {r["target"] for r in rows} == MOUNT_ALL_TARGETS
    assert "left in the Docker VM: 0 loops of ours" in proc.stdout


# --------------------------------------------------------------------------- C-SIB1 (page sharing)

PAGESHARING_PLUGIN = "memdiver.page_sharing.PageSharing"
SIB_SHAPES = {"dropbear": "forked", "gocryptfs": "independent", "openssh": "mixed"}
VVAR_KB = 4  # the PFNMAP [vvar] page: walked and counted in RssKB, skipped by smaps


def _sib_groups(truth) -> dict:
    groups = {}
    for record in truth["siblings"]:
        groups.setdefault(record["group"], []).append(record)
    return groups


def _smaps_kb(record) -> dict:
    lines = record["smaps_rollup_text"].splitlines()[1:]
    return {k: int(v.split()[0]) for k, v in (line.split(":", 1) for line in lines)}


def _assert_private_dirty_equals_smaps(rows, records) -> None:
    by_pid = {r["PID"]: r for r in rows}
    for record in records:
        row, kernel = by_pid[record["pid"]], _smaps_kb(record)
        print("C-SIB1 pid %5d %-9s %-8s private_dirty %5d/%5d kB rss %6d/%6d kB private %.2f%%" % (
            record["pid"], record["group"], record["role"], row["PrivateDirtyKB"],
            kernel["Private_Dirty"], row["RssKB"], kernel["Rss"], row["PrivatePct"]))
        assert row["PrivateDirtyKB"] == kernel["Private_Dirty"], record["pid"]
        assert row["RssKB"] == kernel["Rss"] + VVAR_KB, record["pid"]


def _private_at(document, pid: int, va: int):
    member = next(m for m in document if m["pid"] == pid)
    for start, length, share_class, *_rest in member["classes"]:
        if int(start, 16) <= va < int(start, 16) + length:
            return share_class
    return None


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SIB1_pagesharing_groups_smaps_and_recall(tree, vols, symbol_dirs, claim):
    claim("C-SIB1", tree)
    files, truth = _capture(STEM_V2B)
    groups = _sib_groups(truth)
    pids = [str(r["pid"]) for r in truth["siblings"]]
    rows, out, _res, _truth = _on_capture(vols, tree, claim, STEM_V2B, symbol_dirs,
                                          [PAGESHARING_PLUGIN, "--pid", *pids, "--group", "--dump"])
    found = {}
    for row in rows:
        found.setdefault(row["Group"], []).append(row)
    assert len(found) == 3
    for name, records in groups.items():
        (group,) = [g for g in found.values() if {r["PID"] for r in g} == {r["pid"] for r in records}]
        assert {r["Shape"] for r in group} == {SIB_SHAPES[name]}, name
        assert {r["BuildId"] for r in group} == {records[0]["build_id"][:16]}, name
        _assert_private_dirty_equals_smaps(group, records)
    assert all(r["PatchedCode"] == 0 and r["Smear"] == 0 for r in rows)
    document = json.loads((out / "pagesharing.json").read_text())
    checked = []
    for record in truth["siblings"]:
        for frame in record["frames"]:
            checked.append((record["pid"], frame["secret"],
                            _private_at(document, record["pid"], int(frame["va"], 16))))
    assert len(checked) == 38
    assert all(share_class in ("private_dirty", "private_clean", "private_file_cow")
               for _pid, _secret, share_class in checked), checked
    for member in document:  # the dump holds exactly the private pages, page for page
        size = (out / member["private_file"]).stat().st_size
        assert size == sum(length for _va, length, _off in member["private_runs"])


@pytest.mark.parametrize("tree", sorted(TREES))
def test_C_SIB1_pagesharing_comm_selection_finds_the_three_identities(tree, vols, symbol_dirs, claim):
    claim("C-SIB1", tree)
    _files, truth = _capture(STEM_V2B)
    rows, _out, _res, _truth = _on_capture(vols, tree, claim, STEM_V2B, symbol_dirs,
                                           [PAGESHARING_PLUGIN, "--comm", "dropbear", "sshd",
                                            "gocryptfs", "--group"])
    found = {}
    for row in rows:
        found.setdefault(row["Group"], []).append(row)
    assert len(found) == 3
    for name, records in _sib_groups(truth).items():
        (group,) = [g for g in found.values() if {r["pid"] for r in records} <= {r["PID"] for r in g}]
        assert {r["BuildId"] for r in group} == {records[0]["build_id"][:16]}, name
        print("C-SIB1 --comm group %-9s %d members, shape %s" % (name, len(group), group[0]["Shape"]))
        _assert_private_dirty_equals_smaps(group, records)
