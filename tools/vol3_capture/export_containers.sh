#!/usr/bin/env bash
# export_containers.sh -- pack the encrypted containers planted by secrets_stage.sh
#
# Run INSIDE the guest as root, AFTER the memory dump (it syncs and briefly
# freezes the planted filesystems, which must not happen before the capture).
# Writes OUT/containers.tar (GNU tar --sparse, uncompressed) holding:
#   luks2.img luks1.img veracrypt.hc fscrypt.img   (backing images, if present)
#   ecryptfs_lower/ gocryptfs_cipher/               (lower / cipher directories)
#   samples.sha256                                  (plaintext sample files: sha256 + path)
#   containers_manifest.json                        (member -> kind, size, sha256)
# For a later offline mount proof: open each image with the key recovered from
# the dump and compare the plaintext files against samples.sha256.
#
# Usage: export_containers.sh [--out DIR] [--state DIR]
#   defaults match secrets_stage.sh: --out /var/tmp/memdiver-secrets
#                                    --state /var/lib/memdiver-gt

set -euo pipefail
OUT="/var/tmp/memdiver-secrets"
STATE="/var/lib/memdiver-gt"
ORIG_ARGS=("$@")
while (( $# > 0 )); do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --state) STATE="$2"; shift 2 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done
if (( EUID != 0 )); then
    exec sudo -n bash "$0" "${ORIG_ARGS[@]}"
fi

IMAGES="luks2.img luks1.img veracrypt.hc fscrypt.img"
DIRS="ecryptfs_lower gocryptfs_cipher"
FROZEN_MOUNTS="/mnt/gt_luks2 /mnt/gt_luks1 /mnt/gt_veracrypt /mnt/gt_fscrypt"
TAR="${OUT}/containers.tar"
MANIFEST="${OUT}/containers_manifest.json"
frozen=()

log() { printf '[export_containers %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

thaw() {
    local m
    for m in "${frozen[@]}"; do fsfreeze -u "${m}" 2>/dev/null || true; done
}
trap thaw EXIT

# Flush everything, then freeze each block-backed mount so the images are
# consistent while tar reads them (best effort: vfat may refuse a freeze).
quiesce() {
    local m
    sync
    for m in ${FROZEN_MOUNTS}; do
        mountpoint -q "${m}" || continue
        if timeout 30 fsfreeze -f "${m}" 2>/dev/null; then
            frozen+=("${m}")
        else
            log "fsfreeze ${m} refused; relying on sync"
        fi
    done
}

write_manifest() {   # MEMBER...
    python3 - "${STATE}" "${OUT}" "${MANIFEST}" "$@" <<'PY'
import hashlib, json, os, sys
state, out, manifest, members = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
KINDS = {"luks2.img": "luks2", "luks1.img": "luks1", "veracrypt.hc": "veracrypt",
         "fscrypt.img": "ext4-fscrypt", "ecryptfs_lower": "ecryptfs-lower-dir",
         "gocryptfs_cipher": "gocryptfs-cipher-dir"}
def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()
entries = []
for m in members:
    path = os.path.join(state, m)
    if os.path.isdir(path):
        files = sorted(os.path.relpath(os.path.join(r, f), state)
                       for r, _, fs in os.walk(path) for f in fs)
        entries.append({"member": m, "kind": KINDS.get(m), "type": "dir",
                        "files": {f: digest(os.path.join(state, f)) for f in files}})
    else:
        st = os.stat(path)
        entries.append({"member": m, "kind": KINDS.get(m), "type": "file",
                        "size": st.st_size, "allocated": st.st_blocks * 512,
                        "sha256": digest(path)})
json.dump({"schema": "memdiver-containers/1", "members": entries,
           "samples": "samples.sha256"}, open(manifest, "w"), indent=2)
PY
}

main() {
    local m members=()
    for m in ${IMAGES} ${DIRS}; do
        if [[ -e "${STATE}/${m}" ]]; then members+=("${m}"); else log "absent: ${m}"; fi
    done
    (( ${#members[@]} > 0 )) || { log "nothing to export in ${STATE}"; exit 1; }
    [[ -s "${OUT}/samples.sha256" ]] || log "WARN: no ${OUT}/samples.sha256"
    quiesce
    write_manifest "${members[@]}"
    tar --sparse -cf "${TAR}" -C "${STATE}" "${members[@]}" \
        -C "${OUT}" "$(basename "${MANIFEST}")" \
        $([[ -s "${OUT}/samples.sha256" ]] && echo samples.sha256)
    thaw; frozen=()
    chmod 644 "${TAR}"
    log "wrote ${TAR} ($(stat -c %s "${TAR}") bytes): ${members[*]}"
}

main
