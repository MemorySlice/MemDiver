#!/bin/bash
# Mount proof: keys recovered from a capture's memory image by the vol3plugins open the
# capture's real encrypted containers, and the planted files hash-match samples.sha256.
#
#   tools/vol3_capture/mount_proof.sh --stem CORPUS_DIR/STEM --work DIR [--plugins DIR] [--vol VOL]
#
# STEM.{lime,isf.json,ps_at_dump.txt,containers.tar} must exist (capture v2). Steps:
#   1. extract STEM.containers.tar (sparse) into WORK/containers;
#   2. run the plugins on STEM.lime (unless --plugins names a directory that already holds
#      their outputs): linux.dmcrypt --export dmsetup|cryptsetup|masterkey, linux.fscrypt
#      --export json, linux.ecryptfs --export fek, and samples/plugins/memdiver_gocryptfs.py
#      --pid <gocryptfs daemon from ps_at_dump> --oracle-sample gocryptfs_cipher --export;
#   3. build the mount_proof/ Docker image; run mount_proof/kernel_proof.sh in a
#      --privileged container (dm-crypt via the exact dmsetup table and via the generated
#      cryptsetup scripts, fscrypt v1 via the kernel ioctl, gocryptfs via FUSE);
#   4. run mount_proof_userspace.py in an UNprivileged container (dm-crypt decrypted in
#      userspace for LUKS2/ext4 and VeraCrypt/vfat, eCryptfs from the per-file FEKs,
#      fscrypt v2 from the HKDF-PRK midstates);
#   5. print the claim table (WORK/results.jsonl); exit 0 only if every row matched.
# Every key comes from a plugin export; the capture's secrets.json sidecar is never read.
# Env: MOUNT_PROOF_APT_PROXY (default http://http.docker.internal:3128, Docker Desktop),
#      MOUNT_PROOF_IMAGE (default memdiver-mount-proof:1), MEMDIVER_VOL3_VOL (vol to use).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
IMAGE=${MOUNT_PROOF_IMAGE:-memdiver-mount-proof:1}
PROXY=${MOUNT_PROOF_APT_PROXY-http://http.docker.internal:3128}
VOL=${MEMDIVER_VOL3_VOL:-vol}
STEM="" WORK="" PLUGINS=""

while [ $# -gt 0 ]; do
    case $1 in
        --stem) STEM=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --vol) VOL=$2; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$STEM" ] && [ -n "$WORK" ] || { echo "usage: $0 --stem CORPUS_DIR/STEM --work DIR" >&2; exit 2; }
for ext in lime isf.json ps_at_dump.txt containers.tar; do
    [ -f "$STEM.$ext" ] || { echo "missing $STEM.$ext" >&2; exit 2; }
done
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
PLUGINS=${PLUGINS:-$WORK/plugins}
PY="$(command -v python3)"
USERSPACE=(python3 /tools/mount_proof_userspace.py)

step() { echo; echo "=== $*"; }

extract_containers() {
    step "1. containers.tar -> $WORK/containers"
    mkdir -p "$WORK/containers"
    [ -f "$WORK/containers/samples.sha256" ] || tar -xSf "$STEM.containers.tar" -C "$WORK/containers"
}

run_vol() {   # run_vol NAME PLUGIN_DIR PLUGIN ARGS...   (fresh cache, own output dir)
    local name=$1 pdir=$2; shift 2
    mkdir -p "$PLUGINS/$name" "$WORK/cache/$name"
    ( cd "$PLUGINS/$name" && "$VOL" -q -p "$pdir" -s "$WORK/sym" --offline \
        --cache-path "$WORK/cache/$name" -o "$PLUGINS/$name" -f "$STEM.lime" -r json "$@" \
        > stdout.json 2> stderr.txt ) || { echo "vol $name failed (see $PLUGINS/$name/stderr.txt)"; return 1; }
    echo "vol $name: done"
}

run_plugins() {
    step "2. plugins on $(basename "$STEM").lime ($VOL)"
    if [ -f "$PLUGINS/dm_dmsetup/dmcrypt.dmsetup.txt" ]; then echo "reusing $PLUGINS"; return; fi
    mkdir -p "$WORK/sym/linux"
    ln -sf "$STEM.isf.json" "$WORK/sym/linux/$(basename "$STEM").json"
    local pid pids=()
    pid=$("$PY" "$HERE/mount_proof_userspace.py" daemon-pid --ps "$STEM.ps_at_dump.txt" \
          --command /usr/bin/gocryptfs)
    run_vol dm_dmsetup "$REPO/vol3plugins" linux.dmcrypt --export dmsetup & pids+=($!)
    run_vol dm_cryptsetup "$REPO/vol3plugins" linux.dmcrypt --export cryptsetup & pids+=($!)
    run_vol dm_masterkey "$REPO/vol3plugins" linux.dmcrypt --export masterkey & pids+=($!)
    run_vol fscrypt "$REPO/vol3plugins" linux.fscrypt --export json & pids+=($!)
    run_vol ec_fek "$REPO/vol3plugins" linux.ecryptfs --export fek & pids+=($!)
    run_vol gocryptfs "$REPO/samples/plugins" memdiver_gocryptfs --pid "$pid" \
        --oracle-sample "$WORK/containers/gocryptfs_cipher" --export & pids+=($!)
    local rc=0 p
    for p in "${pids[@]}"; do wait "$p" || rc=1; done
    return $rc
}

build_image() {
    step "3. docker image $IMAGE"
    docker build -q ${PROXY:+--build-arg APT_PROXY=$PROXY} -t "$IMAGE" "$HERE/mount_proof" >/dev/null
}

kernel_proof() {
    step "3. kernel path (privileged container)"
    docker run --rm --privileged -v /dev:/dev -v "$WORK:/work" -v "$PLUGINS:/work/plugins" \
        -v "$HERE:/tools:ro" "$IMAGE" bash /tools/mount_proof/kernel_proof.sh || return 1
}

userspace_proof() {
    step "4. userspace path (unprivileged container)"
    local common=(--samples /work/containers/samples.sha256 --results /work/results.jsonl)
    docker run --rm -v "$WORK:/work" -v "$PLUGINS:/work/plugins" -v "$HERE:/tools:ro" "$IMAGE" bash -c '
        set -u; rc=0; P=/work/plugins; C=/work/containers; U=/work/userspace
        dm() { "$@" --dmsetup $P/dm_dmsetup/dmcrypt.dmsetup.txt --work $U || rc=1; }
        dm '"${USERSPACE[*]}"' dm-fallback '"${common[*]}"' --target luks2 --method userspace-dm \
           --name gt_luks2 --image $C/luks2.img --key-file $P/dm_masterkey/dmcrypt.gt_luks2.masterkey --fs ext4
        dm '"${USERSPACE[*]}"' dm-fallback '"${common[*]}"' --target veracrypt --method userspace-dm \
           --name gt_veracrypt --image $C/veracrypt.hc --key-file $P/dm_masterkey/dmcrypt.gt_veracrypt.masterkey --fs vfat
        '"${USERSPACE[*]}"' ecryptfs '"${common[*]}"' --target ecryptfs --method userspace-fek \
           --lower $C/ecryptfs_lower --fek-csv $P/ec_fek/ecryptfs_fek.csv --out $U/ecryptfs || rc=1
        '"${USERSPACE[*]}"' fscrypt-v2 '"${common[*]}"' --target fscrypt_v2 --method userspace-hkdf \
           --image $C/fscrypt.img --dir /v2 --fscrypt-json $P/fscrypt/fscrypt.json || rc=1
        rm -rf $U; exit $rc' || return 1
}

extract_containers
run_plugins
build_image
rm -f "$WORK/results.jsonl"
rc=0
kernel_proof || rc=1
userspace_proof || rc=1
step "5. claim table"
"$PY" "$HERE/mount_proof_userspace.py" table --results "$WORK/results.jsonl" || rc=1
echo "MOUNT_PROOF_EXIT=$rc"
exit $rc
