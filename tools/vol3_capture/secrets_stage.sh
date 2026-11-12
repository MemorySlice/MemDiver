#!/usr/bin/env bash
# secrets_stage.sh -- plant known secrets in a Linux guest before a memory dump
#
# Run INSIDE the guest as root (it re-execs itself under sudo), immediately
# before acquiring physical memory with LiME/LEMON/AVML. It sets up and keeps
# LIVE at dump time:
#   1 LUKS2 aes-xts-plain64 + ext4      5 fscrypt v1 + v2 directories (ext4)
#   2 LUKS1 aes-cbc-essiv:sha256 + XFS  6 eCryptfs passphrase mount
#   3 VeraCrypt container (tcrypt)      7 gocryptfs mount
#   4 WireGuard (2 netns + dead peer)   8 OpenSSH + dropbear sessions
#   9 struct layouts (pahole over BTF: wireguard, dm-crypt + dm core,
#     fscrypt, ecryptfs) + kernel identity + paging depth
#  10 SSH Tier A: libssh client <-> paramiko ground-truth peer (K, H, keys)
#  11 (opt-in, --siblings) sibling groups: 4 dropbear sessions (forked),
#     4 OpenSSH sessions (re-exec, monitor + session each), 3 gocryptfs
#     mounts (independent), with per-member PFN frames of every secret
# and writes the ground truth to OUT/secrets.json (schema memdiver-secrets-gt/1,
# see README.md) plus OUT/secrets.tar.gz with the raw artefacts, and
# OUT/samples.sha256 (path + sha256 of every plaintext sample file planted).
# After the dump, export_containers.sh packs the encrypted images for a
# later mount proof.
#
# Usage: secrets_stage.sh [--out DIR] [--state DIR] [--wg-rekey-wait SECS]
#                         [--no-install] [--skip ITEM[,ITEM...]] [--siblings]
#   --out DIR            sidecar dir (default /var/tmp/memdiver-secrets)
#   --state DIR          disk-backed dir for loop images + key files
#                        (default /var/lib/memdiver-gt)
#   --wg-rekey-wait N    seconds to wait for one WireGuard rekey (default 135;
#                        REKEY_AFTER_TIME is 120 s). 0 disables the wait.
#   --no-install         do not apt-get install the toolchain
#   --skip LIST          comma list of: luks2,luks1,veracrypt,wireguard,
#                        fscrypt,ecryptfs,gocryptfs,ssh,ssh_tier_a,btf,
#                        siblings,siblings_frames
#   --siblings           also plant item 11 (sibling groups, capture v2b);
#                        off by default, so older captures are reproducible
#
# Idempotent: key material and images persist in --state and are reused; an
# already-open mapping / mount / session is left as is and only re-recorded.
# Never drops caches. Each item runs isolated: a failure becomes a gaps[]
# entry, not an aborted capture.

set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8   # SSH forwards the host locale; keep tools quiet

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="/var/tmp/memdiver-secrets"
STATE="/var/lib/memdiver-gt"
WG_REKEY_WAIT=135
INSTALL=1
SKIP=","
SIBLINGS=0
VERACRYPT_VERSION="${VERACRYPT_VERSION:-1.26.24}"
ORIG_ARGS=("$@")

while (( $# > 0 )); do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --state) STATE="$2"; shift 2 ;;
        --wg-rekey-wait) WG_REKEY_WAIT="$2"; shift 2 ;;
        --no-install) INSTALL=0; shift ;;
        --skip) SKIP=",$2,"; shift 2 ;;
        --siblings) SIBLINGS=1; shift ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if (( EUID != 0 )); then
    exec sudo -n bash "$0" "${ORIG_ARGS[@]}"
fi

ART="${OUT}/artefacts"
FRAGS="${OUT}/fragments.jsonl"
SIB="${STATE}/siblings"
mkdir -p "${OUT}" "${ART}/keys" "${STATE}"
chmod 700 "${STATE}"
rm -f "${FRAGS}"
SAMPLES="${OUT}/samples.sha256"
: > "${SAMPLES}"
exec > >(tee -a "${OUT}/stage.log") 2>&1

log() { printf '[secrets_stage %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
gt()  { python3 "${HERE}/gt_json.py" "$@"; }
hex_of() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# Create FILE with N random bytes once; later runs reuse it.
ensure_random_key() {
    [[ -s "$1" ]] || { head -c "$2" /dev/urandom > "$1"; chmod 600 "$1"; }
    cp "$1" "${ART}/keys/"
}

# Echo the loop device backing FILE, attaching it (with extra losetup args) if needed.
attach_loop() {
    local file="$1"; shift
    local dev
    dev="$(losetup -j "${file}" -O NAME -n | head -1)"
    [[ -n "${dev}" ]] || dev="$(losetup --find --show "$@" "${file}")"
    echo "${dev}"
}

# Start CMD detached from this SSH session unless PIDFILE names a live process.
start_detached() {
    local pidfile="$1"; shift
    if [[ -s "${pidfile}" ]] && kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
        return 0
    fi
    setsid nohup "$@" </dev/null >>"${STATE}/daemons.log" 2>&1 &
    echo $! > "${pidfile}"
}

# Run one item isolated; a failure is recorded as a gap and does not abort.
run_item() {
    local item="$1" fn="$2" rc
    if [[ "${SKIP}" == *",${item},"* ]]; then
        gt gap "${FRAGS}" "${item}" "skipped via --skip"
        return 0
    fi
    log "--- ${item} ---"
    set +e
    ( set -euo pipefail; "${fn}" )
    rc=$?
    set -e
    if (( rc != 0 )); then
        log "item ${item} FAILED (rc=${rc}); recorded as gap"
        gt gap "${FRAGS}" "${item}" "setup failed with rc=${rc}; see stage.log"
    fi
}

# --------------------------------------------------------------------------
# Toolchain
# --------------------------------------------------------------------------

install_packages() {
    (( INSTALL )) || { log "--no-install: skipping packages"; return 0; }
    command -v apt-get >/dev/null || { gt gap "${FRAGS}" packages "no apt-get; install tools manually"; return 0; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq cryptsetup xfsprogs e2fsprogs dosfstools wireguard-tools \
        ecryptfs-utils gocryptfs keyutils dropbear-bin dwarves openssh-client \
        openssh-server iproute2 iputils-ping curl python3 >/dev/null
}

load_modules() {
    local mod
    for mod in loop dm_crypt wireguard xfs; do
        modprobe "${mod}" 2>/dev/null || log "modprobe ${mod} failed (built-in or missing)"
    done
}

# --------------------------------------------------------------------------
# Items 1-3: dm-crypt
# --------------------------------------------------------------------------

record_dmcrypt() {   # NAME TYPE LOOP IMG MNT FS VK_FILE PASS [KEYRING_VK_JSON]
    local name="$1" type="$2" loop="$3" img="$4" mnt="$5" fs="$6" vkf="$7" pass="$8"
    local table vk halves keyring_ref extra=()
    [[ -n "${9:-}" ]] && extra=(keyring_vk:="$9")
    dmsetup table --showkeys "${name}" > "${ART}/dmsetup_${name}.txt"
    table="$(cat "${ART}/dmsetup_${name}.txt")"
    vk="$(hex_of "${vkf}")"
    halves='[]'
    if [[ "$(awk '{print $4}' <<<"${table}")" == *xts* ]]; then
        halves="[\"${vk:0:${#vk}/2}\",\"${vk:${#vk}/2}\"]"
    fi
    keyring_ref="$(awk '{print $5}' <<<"${table}")"
    [[ "${keyring_ref}" == :* ]] || keyring_ref=""
    gt add "${FRAGS}" dmcrypt name="${name}" type="${type}" \
        cipher="$(awk '{print $4}' <<<"${table}")" key_bytes:="$(( ${#vk} / 2 ))" \
        volume_key_hex="${vk}" key_halves_hex:="${halves}" \
        key_in_kernel_keyring:="$([[ -n "${keyring_ref}" ]] && echo true || echo false)" \
        keyring_ref="${keyring_ref}" passphrase="${pass}" backing_file="${img}" \
        loop_device="${loop}" dm_device="/dev/mapper/${name}" mountpoint="${mnt}" fs="${fs}" \
        dm_table_showkeys="${table}" "${extra[@]}"
    gt key "${FRAGS}" "${name}.volume_key" "dmcrypt-${type}" "${vk}" "dmcrypt:${name}"
}

write_sample_files() {   # DIR LABEL
    local i
    for i in 1 2 3; do
        printf 'memdiver ground truth %s file %s\n' "$2" "$i" > "$1/gt_${2}_${i}.txt"
    done
    head -c 65536 /dev/urandom > "$1/gt_${2}_blob.bin"
    sync -f "$1/gt_${2}_1.txt"
    sha256sum "$1/gt_${2}_"{1,2,3}.txt "$1/gt_${2}_blob.bin" >> "${SAMPLES}"
}

# LUKS2: ask cryptsetup (>= 2.7, --link-vk-to-keyring) to also link the volume key
# into root's user keyring as a readable `user` key, so it survives cryptsetup
# unlinking its own logon key. Echoes the open options to use; the method goes
# to ${STATE}/luks2_vk_method.
luks2_link_vk_opts() {   # DESCRIPTION
    local help
    cryptsetup --version > "${ART}/cryptsetup_version.txt" 2>&1 || true
    help="$(cryptsetup --help 2>&1 || true)"   # not `| grep -q`: SIGPIPE + pipefail = false
    if grep -q -- '--link-vk-to-keyring' <<<"${help}"; then
        grep -A2 -- '--link-vk-to-keyring' <<<"${help}" > "${ART}/cryptsetup_link_vk_help.txt" || true
        echo "cryptsetup --link-vk-to-keyring" > "${STATE}/luks2_vk_method"
        printf '%s\n' "--link-vk-to-keyring" "@u::%user:$1"
    else
        echo "keyctl padd user (fallback: cryptsetup lacks --link-vk-to-keyring)" > "${STATE}/luks2_vk_method"
    fi
}

# Echo the keyring_vk JSON for DESCRIPTION; add the key with keyctl if absent.
luks2_keyring_vk() {   # DESCRIPTION VK_FILE
    local id method payload
    id="$(keyctl search @u user "$1" 2>/dev/null || true)"
    if [[ -z "${id}" ]]; then
        id="$(keyctl padd user "$1" @u < "$2")"
        echo "keyctl padd user (fallback: the key was not in @u after cryptsetup open)" > "${STATE}/luks2_vk_method"
    fi
    method="$(cat "${STATE}/luks2_vk_method" 2>/dev/null || echo unknown)"
    payload="$(keyctl pipe "${id}" | od -An -v -tx1 | tr -d ' \n')"
    keyctl describe "${id}" > "${ART}/keyring_vk_describe.txt" 2>&1 || true
    python3 -c 'import json,sys; a=sys.argv; print(json.dumps({"description": a[1], "type": "user",
        "key_id": int(a[2]), "keyring": "@u (root user keyring)", "method": a[3],
        "describe": a[4], "payload_matches_volume_key": a[5] == a[6]}))' \
        "$1" "${id}" "${method}" "$(cat "${ART}/keyring_vk_describe.txt")" "${payload}" "$(hex_of "$2")"
}

item_luks2() {
    local img="${STATE}/luks2.img" vkf="${STATE}/luks2.vk" pass="memdiver-luks2-pass" loop
    ensure_random_key "${vkf}" 64
    if [[ ! -s "${img}" ]]; then
        truncate -s 64M "${img}"
        printf '%s' "${pass}" | cryptsetup luksFormat --batch-mode --type luks2 \
            --cipher aes-xts-plain64 --key-size 512 --volume-key-file "${vkf}" \
            --pbkdf argon2id --pbkdf-memory 65536 --iter-time 200 --key-file=- "${img}"
    fi
    loop="$(attach_loop "${img}")"
    local vk_desc link_opts=()
    vk_desc="cryptsetup:$(cryptsetup luksUUID "${img}")-d0"
    mapfile -t link_opts < <(luks2_link_vk_opts "${vk_desc}")
    [[ -e /dev/mapper/gt_luks2 ]] || printf '%s' "${pass}" | \
        cryptsetup open --type luks2 --key-file=- "${link_opts[@]}" "${loop}" gt_luks2
    blkid /dev/mapper/gt_luks2 >/dev/null || mkfs.ext4 -q /dev/mapper/gt_luks2
    mkdir -p /mnt/gt_luks2
    mountpoint -q /mnt/gt_luks2 || mount /dev/mapper/gt_luks2 /mnt/gt_luks2
    write_sample_files /mnt/gt_luks2 luks2
    cryptsetup luksDump "${loop}" > "${ART}/luksDump_gt_luks2.txt"
    record_dmcrypt gt_luks2 luks2 "${loop}" "${img}" /mnt/gt_luks2 ext4 "${vkf}" "${pass}" \
        "$(luks2_keyring_vk "${vk_desc}" "${vkf}")"
}

item_luks1() {
    local img="${STATE}/luks1.img" vkf="${STATE}/luks1.vk" pass="memdiver-luks1-pass" loop
    ensure_random_key "${vkf}" 32
    if [[ ! -s "${img}" ]]; then
        truncate -s 320M "${img}"   # mkfs.xfs refuses < 300 MB
        printf '%s' "${pass}" | cryptsetup luksFormat --batch-mode --type luks1 \
            --cipher aes-cbc-essiv:sha256 --key-size 256 --volume-key-file "${vkf}" \
            --iter-time 200 --key-file=- "${img}"
    fi
    loop="$(attach_loop "${img}" --direct-io=off)"
    [[ -e /dev/mapper/gt_luks1 ]] || printf '%s' "${pass}" | \
        cryptsetup open --type luks1 --key-file=- "${loop}" gt_luks1
    blkid /dev/mapper/gt_luks1 >/dev/null || mkfs.xfs -q /dev/mapper/gt_luks1
    mkdir -p /mnt/gt_luks1
    mountpoint -q /mnt/gt_luks1 || mount /dev/mapper/gt_luks1 /mnt/gt_luks1
    write_sample_files /mnt/gt_luks1 luks1
    cryptsetup luksDump "${loop}" > "${ART}/luksDump_gt_luks1.txt"
    record_dmcrypt gt_luks1 luks1 "${loop}" "${img}" /mnt/gt_luks1 xfs "${vkf}" "${pass}"
}

ensure_veracrypt() {
    command -v veracrypt >/dev/null && return 0
    local deb_arch url deb="${STATE}/veracrypt-console.deb"
    case "$(uname -m)" in
        aarch64) deb_arch=arm64 ;; x86_64) deb_arch=amd64 ;;
        *) echo "no VeraCrypt build for $(uname -m)"; return 1 ;;
    esac
    # shellcheck disable=SC1091
    . /etc/os-release
    url="https://launchpad.net/veracrypt/trunk/${VERACRYPT_VERSION}/+download/veracrypt-console-${VERACRYPT_VERSION}-${NAME%% *}-${VERSION_ID}-${deb_arch}.deb"
    [[ -s "${deb}" ]] || curl -fsSL -o "${deb}" "${url}"
    echo "${url} sha256=$(sha256sum "${deb}" | cut -d' ' -f1)" > "${ART}/veracrypt_source.txt"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${deb}" >/dev/null
}

item_veracrypt() {
    local img="${STATE}/veracrypt.hc" pass="memdiver-veracrypt-pass" loop table
    if ! ensure_veracrypt; then
        gt gap "${FRAGS}" veracrypt "veracrypt console binary unobtainable for this distro/arch; container not created"
        return 0
    fi
    if [[ ! -s "${img}" ]]; then
        veracrypt --text --non-interactive --create "${img}" --size=64M \
            --password="${pass}" --encryption=AES --hash=SHA-512 --filesystem=FAT \
            --pim=0 --keyfiles= --random-source=/dev/urandom --volume-type=normal
    fi
    loop="$(attach_loop "${img}")"
    # For TCRYPT, --key-file means VeraCrypt keyfiles; the passphrase comes on stdin.
    [[ -e /dev/mapper/gt_veracrypt ]] || printf '%s\n' "${pass}" | \
        cryptsetup open --type tcrypt --veracrypt "${loop}" gt_veracrypt
    mkdir -p /mnt/gt_veracrypt
    mountpoint -q /mnt/gt_veracrypt || mount -t vfat /dev/mapper/gt_veracrypt /mnt/gt_veracrypt
    write_sample_files /mnt/gt_veracrypt veracrypt
    printf '%s\n' "${pass}" | cryptsetup tcryptDump --veracrypt "${loop}" \
        > "${ART}/tcryptDump_gt_veracrypt.txt" 2>&1 || true
    table="$(dmsetup table --showkeys gt_veracrypt)"
    python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' \
        "$(awk '{print $5}' <<<"${table}")" > "${STATE}/veracrypt.vk"
    cp "${STATE}/veracrypt.vk" "${ART}/keys/"
    record_dmcrypt gt_veracrypt tcrypt-veracrypt "${loop}" "${img}" /mnt/gt_veracrypt vfat \
        "${STATE}/veracrypt.vk" "${pass}"
}

# --------------------------------------------------------------------------
# Item 4: WireGuard -- started first, finished last (rekey wait overlaps)
# --------------------------------------------------------------------------

WG_A=gtwgA
WG_B=gtwgB

wg_keys() {
    local k
    for k in A B C; do
        [[ -s "${STATE}/wg${k}.key" ]] || { (umask 077; wg genkey > "${STATE}/wg${k}.key"); }
        wg pubkey < "${STATE}/wg${k}.key" > "${STATE}/wg${k}.pub"
    done
    [[ -s "${STATE}/wg.psk" ]] || { (umask 077; wg genpsk > "${STATE}/wg.psk"); }
}

wg_topology() {
    local netns
    netns="$(ip netns list)"   # not `| grep -qw`: SIGPIPE + pipefail = false
    grep -qw "${WG_A}" <<<"${netns}" && return 0
    ip netns add "${WG_A}"; ip netns add "${WG_B}"
    ip link add gtvethA netns "${WG_A}" type veth peer name gtvethB netns "${WG_B}"
    ip -n "${WG_A}" addr add 10.199.0.1/24 dev gtvethA
    ip -n "${WG_B}" addr add 10.199.0.2/24 dev gtvethB
    ip -n "${WG_A}" link set lo up; ip -n "${WG_A}" link set gtvethA up
    ip -n "${WG_B}" link set lo up; ip -n "${WG_B}" link set gtvethB up
    # Peer C's endpoint (TEST-NET-1) is routed into B, which drops it: the
    # initiation leaves, no response ever comes -> a handshake stays in flight.
    ip -n "${WG_A}" route add default via 10.199.0.2
    ip -n "${WG_A}" link add wg0 type wireguard
    ip -n "${WG_B}" link add wg0 type wireguard
    ip netns exec "${WG_A}" wg set wg0 private-key "${STATE}/wgA.key" listen-port 51820 \
        peer "$(cat "${STATE}/wgB.pub")" preshared-key "${STATE}/wg.psk" \
            endpoint 10.199.0.2:51820 allowed-ips 10.200.0.2/32 persistent-keepalive 5 \
        peer "$(cat "${STATE}/wgC.pub")" endpoint 192.0.2.1:51820 \
            allowed-ips 10.200.0.3/32 persistent-keepalive 5
    ip netns exec "${WG_B}" wg set wg0 private-key "${STATE}/wgB.key" listen-port 51820 \
        peer "$(cat "${STATE}/wgA.pub")" preshared-key "${STATE}/wg.psk" \
            endpoint 10.199.0.1:51820 allowed-ips 10.200.0.1/32
    ip -n "${WG_A}" addr add 10.200.0.1/24 dev wg0; ip -n "${WG_A}" link set wg0 up
    ip -n "${WG_B}" addr add 10.200.0.2/24 dev wg0; ip -n "${WG_B}" link set wg0 up
}

item_wireguard_start() {
    wg_keys
    wg_topology
    start_detached "${STATE}/wg_ping_B.pid" ip netns exec "${WG_A}" ping -i 1 10.200.0.2
    start_detached "${STATE}/wg_ping_C.pid" ip netns exec "${WG_A}" ping -i 2 10.200.0.3
    local i
    for i in $(seq 1 20); do
        [[ "$(ip netns exec "${WG_A}" wg show wg0 latest-handshakes | awk 'NR==1{print $2}')" != 0 ]] && break
        sleep 1
    done
    ip netns exec "${WG_A}" wg show wg0 latest-handshakes > "${STATE}/wg_first_handshake.txt"
    log "wireguard: first handshake $(cat "${STATE}/wg_first_handshake.txt" | tr '\n' ' ')"
}

item_wireguard_finish() {
    local first now waited=0 rekeyed=false pub_b
    pub_b="$(cat "${STATE}/wgB.pub")"
    first="$(awk -v p="${pub_b}" '$1==p{print $2}' "${STATE}/wg_first_handshake.txt")"
    while (( waited < WG_REKEY_WAIT )); do
        now="$(ip netns exec "${WG_A}" wg show wg0 latest-handshakes | awk -v p="${pub_b}" '$1==p{print $2}')"
        if [[ -n "${first}" && "${first}" != 0 && "${now}" -gt "${first}" ]]; then
            rekeyed=true; break
        fi
        sleep 5; waited=$(( waited + 5 ))
    done
    log "wireguard: rekey observed=${rekeyed} after ${waited}s"
    local ns role
    for ns in "${WG_A}" "${WG_B}"; do
        ip netns exec "${ns}" wg show all dump > "${ART}/wg_dump_${ns}.txt"
        role='"responder-side peer of A"'
        [[ "${ns}" == "${WG_A}" ]] && role='"initiator; peer C endpoint 192.0.2.1 is unreachable (handshake in flight)"'
        gt wg "${FRAGS}" "${ns}" "${ART}/wg_dump_${ns}.txt" \
            "{\"role\": ${role}, \"rekey_observed\": ${rekeyed}, \"first_handshake_unix\": ${first:-0}}"
    done
    local k
    for k in A B C; do
        gt key "${FRAGS}" "wireguard.${k}.private" wireguard-x25519-private \
            "$(base64 -d < "${STATE}/wg${k}.key" | od -An -v -tx1 | tr -d ' \n')" "wireguard:wg${k}" \
            "$([[ ${k} == C ]] && echo 'phantom peer; key never configured on an interface' || echo "netns gtwg${k}")"
    done
    gt key "${FRAGS}" wireguard.psk wireguard-psk \
        "$(base64 -d < "${STATE}/wg.psk" | od -An -v -tx1 | tr -d ' \n')" "wireguard:A<->B"
}

# --------------------------------------------------------------------------
# Item 5: fscrypt v1 + v2
# --------------------------------------------------------------------------

item_fscrypt() {
    local img="${STATE}/fscrypt.img" mnt=/mnt/gt_fscrypt loop desc ident
    ensure_random_key "${STATE}/fscrypt_v1.key" 64
    ensure_random_key "${STATE}/fscrypt_v2.key" 64
    # v1 descriptor = SHA-512(SHA-512(raw))[:8], as e4crypt/fscryptctl/fscrypt derive it,
    # so the descriptor is provable from the key alone.
    [[ -s "${STATE}/fscrypt_v1.desc" ]] || python3 "${HERE}/fscrypt_helper.py" descriptor \
        "${STATE}/fscrypt_v1.key" > "${STATE}/fscrypt_v1.desc"
    if [[ ! -s "${img}" ]]; then
        truncate -s 128M "${img}"
        mkfs.ext4 -q -O encrypt "${img}"
    fi
    loop="$(attach_loop "${img}")"
    mkdir -p "${mnt}"
    mountpoint -q "${mnt}" || mount "${loop}" "${mnt}"
    desc="$(python3 "${HERE}/fscrypt_helper.py" add-key "${mnt}" "${STATE}/fscrypt_v1.key" v1 "$(cat "${STATE}/fscrypt_v1.desc")")"
    ident="$(python3 "${HERE}/fscrypt_helper.py" add-key "${mnt}" "${STATE}/fscrypt_v2.key" v2)"
    local legacy derived v1_extra=()
    legacy="$(fscrypt_legacy_logon_key "${desc}")"
    derived=false
    [[ "${desc}" == "$(python3 "${HERE}/fscrypt_helper.py" descriptor "${STATE}/fscrypt_v1.key")" ]] && derived=true
    local ver ref dir
    for ver in v1 v2; do
        dir="${mnt}/${ver}"
        ref="${desc}"; [[ "${ver}" == v2 ]] && ref="${ident}"
        v1_extra=()
        [[ "${ver}" == v1 ]] && v1_extra=(descriptor_derived:="${derived}" \
            descriptor_derivation="sha512(sha512(master_key))[:8]" legacy_logon_key:="${legacy}")
        if [[ ! -d "${dir}" ]]; then
            mkdir "${dir}"
            python3 "${HERE}/fscrypt_helper.py" set-policy "${dir}" "${ver}" "${ref}"
        fi
        write_sample_files "${dir}" "fscrypt_${ver}"
        gt add "${FRAGS}" fscrypt policy_version="${ver}" mountpoint="${mnt}" directory="${dir}" \
            backing_file="${img}" loop_device="${loop}" \
            key_ref_kind="$([[ ${ver} == v1 ]] && echo descriptor || echo identifier)" \
            key_ref_hex="${ref}" master_key_hex="$(hex_of "${STATE}/fscrypt_${ver}.key")" \
            contents_mode=AES-256-XTS filenames_mode=AES-256-CTS flags=PAD_16 \
            keyring=filesystem "${v1_extra[@]}"
        gt key "${FRAGS}" "fscrypt.${ver}.master_key" "fscrypt-${ver}-master" \
            "$(hex_of "${STATE}/fscrypt_${ver}.key")" "fscrypt:${dir}" "key_ref=${ref}"
    done
}

# Also add the v1 master key the legacy way: a `logon fscrypt:<descriptor>` key
# (payload struct fscrypt_key) in root's user keyring. Echoes its JSON record.
fscrypt_legacy_logon_key() {   # DESCRIPTOR_HEX
    local id payload="${STATE}/fscrypt_v1.legacy"
    python3 "${HERE}/fscrypt_helper.py" legacy-payload "${STATE}/fscrypt_v1.key" "${payload}"
    chmod 600 "${payload}"
    id="$(keyctl search @u logon "fscrypt:$1" 2>/dev/null || keyctl padd logon "fscrypt:$1" @u < "${payload}")"
    python3 -c 'import json,sys; print(json.dumps({"description": "fscrypt:" + sys.argv[1],
        "type": "logon", "key_id": int(sys.argv[2]), "keyring": "@u (root user keyring)",
        "payload": "struct fscrypt_key {u32 mode=1 (AES-256-XTS); u8 raw[64]; u32 size=64}"}))' \
        "$1" "${id}"
}

# --------------------------------------------------------------------------
# Item 6: eCryptfs
# --------------------------------------------------------------------------

item_ecryptfs() {
    local lower="${STATE}/ecryptfs_lower" upper=/mnt/gt_ecryptfs pass="memdiver-ecryptfs-pass"
    local fekek sig mounted_sig
    read -r fekek sig < <(gt ecryptfs-fekek "${pass}")
    mkdir -p "${lower}" "${upper}"
    if ! mountpoint -q "${upper}"; then
        mount -t ecryptfs "${lower}" "${upper}" -o "key=passphrase:passphrase_passwd=${pass},ecryptfs_cipher=aes,ecryptfs_key_bytes=32,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=no,no_sig_cache" </dev/null
    fi
    write_sample_files "${upper}" ecryptfs
    mounted_sig="$(awk -v m="${upper}" '$2==m{print $4}' /proc/mounts | tr ',' '\n' | sed -n 's/^ecryptfs_sig=//p' | head -1)"
    gt add "${FRAGS}" ecryptfs lower_dir="${lower}" mountpoint="${upper}" passphrase="${pass}" \
        cipher=aes key_bytes:=32 salt_hex=0011223344556677 \
        fekek_hex="${fekek}" fekek_signature="${sig}" mounted_sig="${mounted_sig}" \
        signature_matches:="$([[ "${sig}" == "${mounted_sig}" ]] && echo true || echo false)"
    gt key "${FRAGS}" ecryptfs.fekek ecryptfs-fekek-sha512 "${fekek}" "ecryptfs:${upper}" "sig=${sig}"
}

# --------------------------------------------------------------------------
# Item 7: gocryptfs
# --------------------------------------------------------------------------

item_gocryptfs() {
    local cipher="${STATE}/gocryptfs_cipher" plain=/mnt/gt_gocryptfs pf="${STATE}/gocryptfs.pass" mk
    [[ -s "${pf}" ]] || printf 'memdiver-gocryptfs-pass\n' > "${pf}"
    mkdir -p "${cipher}" "${plain}"
    [[ -s "${cipher}/gocryptfs.conf" ]] || gocryptfs -init -passfile "${pf}" "${cipher}" > "${STATE}/gocryptfs_init.txt" 2>&1
    cp "${STATE}/gocryptfs_init.txt" "${cipher}/gocryptfs.conf" "${ART}/" 2>/dev/null || true
    # -init suppresses the master-key banner off a tty, so decrypt it back out
    # of gocryptfs.conf with the password (gocryptfs-xray ships with gocryptfs).
    gocryptfs-xray -dumpmasterkey "${cipher}/gocryptfs.conf" < "${pf}" > "${ART}/gocryptfs_xray_masterkey.txt" 2>&1
    mk="$(grep -oE '^[0-9a-f]{64}$' "${ART}/gocryptfs_xray_masterkey.txt" | head -1)"
    [[ -n "${mk}" ]] || { echo "could not recover gocryptfs master key"; return 1; }
    mountpoint -q "${plain}" || setsid -w gocryptfs -passfile "${pf}" "${cipher}" "${plain}" </dev/null >>"${STATE}/daemons.log" 2>&1
    write_sample_files "${plain}" gocryptfs
    gocryptfs -info "${cipher}" > "${ART}/gocryptfs_info.txt" 2>&1 || true
    gt add "${FRAGS}" gocryptfs cipher_dir="${cipher}" mountpoint="${plain}" \
        password="$(head -1 "${pf}")" master_key_hex="${mk}" \
        daemon_pids="$(pgrep -d, -f "gocryptfs .*${cipher}" || true)" \
        info@="${ART}/gocryptfs_info.txt"
    gt key "${FRAGS}" gocryptfs.master_key gocryptfs-master "${mk}" "gocryptfs:${cipher}"
}

# --------------------------------------------------------------------------
# Item 8: SSH sessions (OpenSSH server + dropbear server), no traffic capture
# --------------------------------------------------------------------------

ssh_client_record() {   # SERVER_KIND PORT
    local kind="$1" port="$2" log="${STATE}/ssh_${1}_client.log" i server_pids
    start_detached "${STATE}/ssh_${kind}_client.pid" ssh -N -v -E "${log}" \
        -i "${STATE}/gt_ssh_ed25519" -p "${port}" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30 -o BatchMode=yes gtuser@127.0.0.1
    for i in $(seq 1 20); do grep -q 'Authenticated to' "${log}" 2>/dev/null && break; sleep 1; done
    tr -d '\r' < "${log}" > "${ART}/ssh_${kind}_client.log"   # -E writes CRLF
    log="${ART}/ssh_${kind}_client.log"
    if [[ "${kind}" == openssh ]]; then
        server_pids="$(pgrep -d, -f '^sshd: gtuser' || true)"
    else
        server_pids="$(pgrep -d, -P "$(cat "${STATE}/dropbear.pid")" || true)"
    fi
    gt add "${FRAGS}" ssh server="${kind}" port:="${port}" user=gtuser \
        client_pid:="$(cat "${STATE}/ssh_${kind}_client.pid")" \
        server_pids="${server_pids}" \
        authenticated:="$(grep -q 'Authenticated to' "${log}" && echo true || echo false)" \
        kex_algorithm="$(sed -n 's/.*kex: algorithm: //p' "${log}" | head -1)" \
        host_key_algorithm="$(sed -n 's/.*kex: host key algorithm: //p' "${log}" | head -1)" \
        cipher_s2c="$(sed -n 's/.*kex: server->client cipher: //p' "${log}" | head -1)" \
        cipher_c2s="$(sed -n 's/.*kex: client->server cipher: //p' "${log}" | head -1)" \
        server_version="$(sed -n 's/.*Remote protocol version [^,]*, remote software version //p' "${log}" | head -1)" \
        session_keys=unavailable-without-instrumentation
}

# User gtuser with the ed25519 client key authorized (shared by items 8 and 11).
ensure_gtuser() {
    id gtuser >/dev/null 2>&1 || useradd -m -s /bin/bash gtuser
    usermod -p '*' gtuser   # unlocked but password-less: dropbear rejects '!' accounts
    [[ -s "${STATE}/gt_ssh_ed25519" ]] || ssh-keygen -q -t ed25519 -N '' -f "${STATE}/gt_ssh_ed25519"
    install -d -m 700 -o gtuser -g gtuser ~gtuser/.ssh
    install -m 600 -o gtuser -g gtuser "${STATE}/gt_ssh_ed25519.pub" ~gtuser/.ssh/authorized_keys
}

item_ssh() {
    ensure_gtuser
    systemctl start ssh.socket ssh.service 2>/dev/null || systemctl start sshd 2>/dev/null || true
    ssh_client_record openssh 22
    [[ -s "${STATE}/dropbear_ed25519" ]] || dropbearkey -t ed25519 -f "${STATE}/dropbear_ed25519" >/dev/null
    start_detached "${STATE}/dropbear.pid" dropbear -F -E -s -p 127.0.0.1:2022 -r "${STATE}/dropbear_ed25519"
    sleep 1
    ssh_client_record dropbear 2022
}

# --------------------------------------------------------------------------
# Item 8b: SSH Tier A -- libssh client with a K-logging paramiko peer
# --------------------------------------------------------------------------

SSH_TIER_A_PORT=2200

# Start CMD detached with its own stdout/stderr log unless PIDFILE names a live process.
start_detached_log() {   # PIDFILE LOGFILE CMD...
    local pidfile="$1" logfile="$2"; shift 2
    if [[ -s "${pidfile}" ]] && kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
        return 0
    fi
    setsid nohup "$@" </dev/null >"${logfile}" 2>&1 &
    echo $! > "${pidfile}"
}

wait_for_line() {   # FILE PATTERN SECONDS
    local i
    for i in $(seq 1 "$3"); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 1; done
    echo "timeout waiting for '$2' in $1"; cat "$1" 2>/dev/null; return 1
}

item_ssh_tier_a() {
    local dir="${STATE}/ssh_tier_a" src="${HERE}/ssh_tier_a" spid cpid
    mkdir -p "${dir}"
    if (( INSTALL )); then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            gcc libc6-dev libssh-dev python3-paramiko >/dev/null
    fi
    [[ -x "${dir}/libssh_client" ]] || gcc -O0 -g -o "${dir}/libssh_client" "${src}/libssh_client.c" -lssh
    cp "${src}/gt_server.py" "${dir}/gt_server.py"
    if ! { [[ -s "${dir}/server.pid" ]] && kill -0 "$(cat "${dir}/server.pid")" 2>/dev/null; }; then
        rm -f "${dir}/events.jsonl"
    fi
    start_detached_log "${dir}/server.pid" "${dir}/server.log" \
        python3 "${dir}/gt_server.py" "${SSH_TIER_A_PORT}" "${dir}/events.jsonl"
    wait_for_line "${dir}/server.log" READY 180
    start_detached_log "${dir}/client.pid" "${dir}/client.log" \
        "${dir}/libssh_client" "${SSH_TIER_A_PORT}"
    wait_for_line "${dir}/client.log" READY 180
    spid="$(cat "${dir}/server.pid")"; cpid="$(cat "${dir}/client.pid")"
    kill -0 "${cpid}"   # the client must still be connected and idle
    cp "${dir}/events.jsonl" "${ART}/ssh_tier_a_events.jsonl"
    cp "${dir}/client.log" "${ART}/ssh_tier_a_client.log"
    cp "${dir}/server.log" "${ART}/ssh_tier_a_server.log"
    dpkg-query -W libssh-4 python3-paramiko > "${ART}/ssh_tier_a_versions.txt" 2>&1 || true
    gt ssh-tier-a "${FRAGS}" "${dir}/events.jsonl" "${dir}/client.log" "${cpid}" "${spid}"
}

# --------------------------------------------------------------------------
# Item 11 (opt-in, --siblings): sibling groups -- several live instances of one
# binary in one image, the in-image stand-in for N captures (capture v2b)
# --------------------------------------------------------------------------

SIB_DROPBEAR_PORT=2023
SIB_SSHD_PORT=2201
SIB_SESSIONS=4
SIB_GOCRYPTFS_MOUNTS=3

wait_for_listen() {   # PORT SECONDS
    local i
    for i in $(seq 1 "$2"); do
        [[ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]] && return 0
        sleep 1
    done
    echo "nothing listens on port $1 after $2 s"; return 1
}

sibling_group_file() {   # GROUP SHAPE LISTENER_PID SERVER_PORT
    python3 -c 'import json,sys; a=sys.argv; json.dump({"group": a[1], "expected_shape": a[2],
        "listener_pid": int(a[3]), "server_port": int(a[4])}, open(a[5], "w"))' \
        "$1" "$2" "$3" "$4" "${SIB}/group_$1.json"
}

# SESSIONS concurrent connections, one paramiko ground-truth client each, made one
# after the other; each stays authenticated and idle (no channel, like ssh -N).
sibling_ssh_connections() {   # GROUP PORT
    local group="$1" port="$2" i id
    for i in $(seq 1 "${SIB_SESSIONS}"); do
        id="${group}-${i}"
        if ! { [[ -s "${SIB}/client_${id}.pid" ]] && kill -0 "$(cat "${SIB}/client_${id}.pid")" 2>/dev/null; }; then
            rm -f "${SIB}/events_${id}.jsonl"
        fi
        start_detached_log "${SIB}/client_${id}.pid" "${SIB}/client_${id}.log" \
            python3 "${HERE}/siblings/gt_ssh_client.py" 127.0.0.1 "${port}" gtuser \
            "${STATE}/gt_ssh_ed25519" "${SIB}/events_${id}.jsonl" "${group}" "${id}"
        wait_for_line "${SIB}/client_${id}.log" READY 300   # TCG: paramiko import + kex is slow
    done
}

# dropbear forks one child per connection from one listener (no re-exec): "forked".
sibling_dropbear() {
    [[ -s "${STATE}/dropbear_ed25519" ]] || dropbearkey -t ed25519 -f "${STATE}/dropbear_ed25519" >/dev/null
    start_detached "${SIB}/dropbear.pid" dropbear -F -E -s -p "127.0.0.1:${SIB_DROPBEAR_PORT}" \
        -r "${STATE}/dropbear_ed25519"
    wait_for_listen "${SIB_DROPBEAR_PORT}" 30
    sibling_group_file dropbear forked "$(cat "${SIB}/dropbear.pid")" "${SIB_DROPBEAR_PORT}"
    sibling_ssh_connections dropbear "${SIB_DROPBEAR_PORT}"
}

# A dedicated sshd (not the system one, so the group is only these 4 connections).
# OpenSSH 9.x re-execs itself per connection: a privileged monitor plus the
# post-auth session process per connection: "reexec".
sibling_openssh() {
    mkdir -p /run/sshd && chmod 755 /run/sshd
    ssh-keygen -A >/dev/null   # creates only missing host keys
    start_detached "${SIB}/sshd.pid" /usr/sbin/sshd -D -e -p "${SIB_SSHD_PORT}" \
        -o ListenAddress=127.0.0.1 -o PidFile="${SIB}/sshd_self.pid"
    wait_for_listen "${SIB_SSHD_PORT}" 30
    sibling_group_file openssh reexec "$(cat "${SIB}/sshd.pid")" "${SIB_SSHD_PORT}"
    sibling_ssh_connections openssh "${SIB_SSHD_PORT}"
}

# Independent gocryptfs mounts: separate vaults, one daemon process each.
sibling_gocryptfs_mount() {   # N
    local n="$1" id="gocryptfs-$1" mk pid
    local cipher="${STATE}/sib_gocryptfs_cipher_$1" plain="/mnt/gt_sib_gocryptfs_$1"
    local pf="${STATE}/sib_gocryptfs_$1.pass"
    [[ -s "${pf}" ]] || printf 'memdiver-sib-gocryptfs-%s-pass\n' "${n}" > "${pf}"
    mkdir -p "${cipher}" "${plain}"
    [[ -s "${cipher}/gocryptfs.conf" ]] || gocryptfs -init -passfile "${pf}" "${cipher}" \
        > "${SIB}/gocryptfs_init_${n}.txt" 2>&1
    gocryptfs-xray -dumpmasterkey "${cipher}/gocryptfs.conf" < "${pf}" > "${SIB}/xray_${n}.txt" 2>&1
    mk="$(grep -oE '^[0-9a-f]{64}$' "${SIB}/xray_${n}.txt" | head -1)"
    [[ -n "${mk}" ]] || { echo "could not recover the ${id} master key"; return 1; }
    mountpoint -q "${plain}" || setsid -w gocryptfs -passfile "${pf}" "${cipher}" "${plain}" \
        </dev/null >>"${STATE}/daemons.log" 2>&1
    printf 'memdiver sibling %s\n' "${id}" > "${plain}/gt_${id}.txt"
    sync -f "${plain}/gt_${id}.txt"
    pid="$(pgrep -d, -f -- "${cipher} ${plain}\$" || true)"
    [[ "${pid}" =~ ^[0-9]+$ ]] || { echo "${id}: expected one daemon pid, got '${pid}'"; return 1; }
    cp "${cipher}/gocryptfs.conf" "${ART}/sib_gocryptfs_${n}.conf"
    python3 -c 'import json,sys; a=sys.argv; flags=json.load(open(a[6])).get("FeatureFlags", [])
cipher="xchacha20-poly1305" if "XChaCha20Poly1305" in flags else "aes-siv" if "AESSIV" in flags else "aes-256-gcm"
json.dump({"group": "gocryptfs", "conn_id": a[1], "mountpoint": a[2], "cipher_dir": a[3],
    "password": open(a[4]).read().strip(), "master_key_hex": a[5], "cipher": cipher,
    "feature_flags": flags, "daemon_pid": int(a[7])}, open(a[8], "w"))' \
        "${id}" "${plain}" "${cipher}" "${pf}" "${mk}" "${cipher}/gocryptfs.conf" "${pid}" \
        "${SIB}/mount_${id}.json"
    echo "{\"group\": \"gocryptfs\", \"expected_shape\": \"independent\"}" > "${SIB}/group_gocryptfs.json"
}

item_siblings() {
    mkdir -p "${SIB}"
    rm -f "${SIB}"/group_*.json "${SIB}"/mount_*.json
    if (( INSTALL )); then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            python3-paramiko dropbear-bin openssh-server gocryptfs iproute2 >/dev/null
    fi
    ensure_gtuser
    sibling_dropbear
    sibling_openssh
    local n
    for n in $(seq 1 "${SIB_GOCRYPTFS_MOUNTS}"); do sibling_gocryptfs_mount "${n}"; done
    gt sibling-plan "${SIB}" "${SIB}/plan.json"
    python3 "${HERE}/sibling_frames.py" discover "${SIB}/plan.json"
}

# Run last, right before the dump: identity, liveness, smaps_rollup and PFN frames
# of every member's secrets, folded into siblings[] (+ keys[]).
item_siblings_frames() {
    [[ -s "${SIB}/plan.json" ]] || { echo "no sibling plan (item siblings failed?)"; return 1; }
    python3 "${HERE}/sibling_frames.py" collect "${SIB}/plan.json" "${SIB}/collected.json"
    cp "${SIB}/plan.json" "${ART}/siblings_plan.json"
    cp "${SIB}/collected.json" "${ART}/siblings_collected.json"
    gt siblings "${FRAGS}" "${SIB}/plan.json" "${SIB}/collected.json"
}

# --------------------------------------------------------------------------
# Item 9: struct layouts + kernel identity
# --------------------------------------------------------------------------

WG_STRUCTS="wg_device wg_peer noise_handshake noise_keypair noise_static_identity
    noise_keypairs noise_symmetric_key cookie_checker cookie index_hashtable_entry
    allowedips_node"
DM_CORE_STRUCTS="mapped_device dm_table dm_target dm_dev hash_cell"
VMLINUX_STRUCTS="fscrypt_master_key ecryptfs_crypt_stat ecryptfs_auth_tok"

pahole_struct() {   # STRUCT BTF_NAME
    local out="${ART}/pahole_${1}.txt" src="/sys/kernel/btf/$2"
    if [[ "$2" == vmlinux ]]; then
        pahole -C "$1" "${src}" > "${out}" 2>&1
    else
        pahole --btf_base /sys/kernel/btf/vmlinux -C "$1" "${src}" > "${out}" 2>&1
    fi
    grep -q "^struct $1 {" "${out}" || { gt gap "${FRAGS}" "btf:$1" "pahole found no struct $1 in ${src}"; return 0; }
    gt btf "${FRAGS}" "btf:$2" "${out}"
}

item_btf() {
    uname -a > "${ART}/uname_a.txt"
    cat /proc/cmdline > "${ART}/proc_cmdline.txt"
    lsmod > "${ART}/lsmod.txt"
    python3 "${HERE}/paging_probe.py" > "${ART}/paging.json"
    grep -E '^[[:xdigit:]]+ . (__pgtable_l5_enabled|pgdir_shift|ptrs_per_p4d|page_offset_base)$' \
        /proc/kallsyms > "${ART}/kallsyms_paging.txt" 2>/dev/null || true
    gt kernel "${FRAGS}" paging "$(cat "${ART}/paging.json")"
    local mod s dm_core=vmlinux
    for mod in dm_crypt dm_mod wireguard; do
        [[ -r "/sys/kernel/btf/${mod}" ]] && cp "/sys/kernel/btf/${mod}" "${ART}/btf_${mod}.bin"
    done
    # dm core lives in dm_mod when device-mapper is a module, else in vmlinux.
    [[ -r /sys/kernel/btf/dm_mod ]] && dm_core=dm_mod
    command -v pahole >/dev/null || { gt gap "${FRAGS}" btf "pahole (dwarves) not installed"; return 0; }
    for s in ${WG_STRUCTS}; do pahole_struct "${s}" wireguard; done
    pahole_struct crypt_config dm_crypt
    for s in ${DM_CORE_STRUCTS}; do pahole_struct "${s}" "${dm_core}"; done
    for s in ${VMLINUX_STRUCTS}; do pahole_struct "${s}" vmlinux; done
}

# --------------------------------------------------------------------------
# Item 10: global ground truth + sidecar
# --------------------------------------------------------------------------

global_ground_truth() {
    dmsetup table --showkeys > "${ART}/dmsetup_table_showkeys.txt" 2>&1 || true
    { echo '== keyctl show @u'; keyctl show @u; echo '== keyctl show @s'; keyctl show @s; } \
        > "${ART}/keyctl_show.txt" 2>&1 || true
    cat /proc/keys > "${ART}/proc_keys.txt" 2>&1 || true
    losetup -a > "${ART}/losetup.txt" 2>&1 || true
    grep -E 'gt_|ecryptfs|gocryptfs' /proc/mounts > "${ART}/mounts.txt" || true
    ps -efww > "${ART}/ps_at_stage.txt"
}

finalize() {
    gt finalize "${FRAGS}" "${OUT}/secrets.json" "$(uname -m)"
    tar -czf "${OUT}/secrets.tar.gz" -C "${OUT}" artefacts stage.log
    chmod 644 "${OUT}/secrets.json" "${OUT}/secrets.tar.gz"
    log "wrote ${OUT}/secrets.json and ${OUT}/secrets.tar.gz"
    log "gaps: $(python3 -c 'import json,sys; print([g["item"] for g in json.load(open(sys.argv[1]))["gaps"]])' "${OUT}/secrets.json")"
}

main() {
    log "start: out=${OUT} state=${STATE} kernel=$(uname -r) arch=$(uname -m)"
    run_item packages install_packages
    load_modules
    # Possess root's user keyring (link @u into this session keyring): its keys
    # grant search/read to the possessor only, so without this the LUKS2 VK
    # and fscrypt legacy key lookups below fail even as root.
    keyctl link @u @s >/dev/null 2>&1 || log "keyctl link @u @s failed"
    run_item wireguard item_wireguard_start
    run_item luks2 item_luks2
    run_item luks1 item_luks1
    run_item veracrypt item_veracrypt
    run_item fscrypt item_fscrypt
    run_item ecryptfs item_ecryptfs
    run_item gocryptfs item_gocryptfs
    run_item ssh item_ssh
    run_item ssh_tier_a item_ssh_tier_a
    if (( SIBLINGS )); then run_item siblings item_siblings; fi
    run_item btf item_btf
    run_item wireguard item_wireguard_finish
    global_ground_truth
    if (( SIBLINGS )); then run_item siblings_frames item_siblings_frames; fi
    finalize
}

main
