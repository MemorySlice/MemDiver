#!/bin/bash
# Privileged half of the mount proof (runs INSIDE the memdiver-mount-proof image).
# Opens every container with the kernel, using only keys from the plugin exports in
# /work/plugins, and hash-checks the planted files. Called by ../mount_proof.sh with
#   docker run --rm --privileged -v /dev:/dev -v WORK:/work -v TOOLS:/tools:ro IMAGE \
#     bash /tools/mount_proof/kernel_proof.sh
# Loop devices, dm targets and keyrings belong to the shared Docker VM: everything this
# script creates is torn down by the EXIT trap (also on failure).
set -uo pipefail

W=/work
C=$W/containers
P=$W/plugins
R=$W/results.jsonl
SAMPLES=$C/samples.sha256
PY=(python3 /tools/mount_proof_userspace.py)
DMSETUP_TXT=$P/dm_dmsetup/dmcrypt.dmsetup.txt

LOOPS=() MAPS=() CRYPTS=() MNTS=() KEYS=()
FAILED=0

RELEASED=0
release() {   # tear down everything the current step created (also the EXIT trap)
    local i m k l
    for ((i = ${#MNTS[@]} - 1; i >= 0; i--)); do umount "${MNTS[i]}" 2>/dev/null || umount -l "${MNTS[i]}" 2>/dev/null; done
    for m in "${CRYPTS[@]}"; do cryptsetup close "$m" 2>/dev/null; done
    for m in "${MAPS[@]}"; do dmsetup remove --noudevsync "$m" 2>/dev/null; done
    for k in "${KEYS[@]}"; do keyctl unlink "$k" @s >/dev/null 2>&1; done
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null; done
    dmsetup mknodes >/dev/null 2>&1
    RELEASED=$((RELEASED + ${#MNTS[@]} + ${#CRYPTS[@]} + ${#MAPS[@]} + ${#KEYS[@]} + ${#LOOPS[@]}))
    LOOPS=() MAPS=() CRYPTS=() MNTS=() KEYS=()
}
on_exit() {
    release
    echo "cleanup: $RELEASED mounts/maps/keys/loops released;" \
         "left in the Docker VM: $(losetup -a | grep -c "/containers/") loops of ours"
}
trap on_exit EXIT

note_fail() { echo "FAIL: $*"; FAILED=1; }

attach_ro() {   # attach_ro FILE -> sets LOOP (no command substitution: LOOPS must persist)
    LOOP=$(losetup -r -f --show "$1") || return 1
    LOOPS+=("$LOOP")
}

mount_ro() {    # mount_ro DEV DIR  (XFS: norecovery, the image was frozen, not unmounted)
    local opts=ro
    [ "$(blkid -o value -s TYPE "$1")" = xfs ] && opts=ro,norecovery
    mkdir -p "$2"
    mount -o "$opts" "$1" "$2" && MNTS+=("$2")
}


hashcheck() {   # hashcheck TARGET METHOD ROOT [NOTE]
    "${PY[@]}" hashcheck --samples "$SAMPLES" --results "$R" --target "$1" --method "$2" \
        --root "$3" --note="${4:-}" || FAILED=1
}

declare -A IMAGE=([gt_luks1]=luks1.img [gt_luks2]=luks2.img [gt_veracrypt]=veracrypt.hc)

dm_via_dmsetup() {   # exact --export dmsetup table; only the backing device is replaced
    local name=$1 target=${1#gt_} majmin table ref kid map=mp_${1#gt_}
    attach_ro "$C/${IMAGE[$name]}" || { note_fail "losetup $name"; return; }
    majmin=$(lsblk -dno MAJ:MIN "$LOOP" | tr -d ' ')
    table=$("${PY[@]}" dm-line --dmsetup "$DMSETUP_TXT" --name "$name" --device "$majmin")
    ref=$("${PY[@]}" dm-line --dmsetup "$DMSETUP_TXT" --name "$name" --keyref)
    if [ -n "$ref" ]; then   # table names a kernel keyring key: load the plugin's key under it
        kid=$(keyctl padd ${ref% *} "${ref#* }" @s < "$P/dm_masterkey/dmcrypt.$name.masterkey") \
            || { note_fail "keyctl $name"; return; }
        KEYS+=("$kid")
        echo "$name: table references keyring key '${ref#* }'; loaded --export masterkey as key $kid"
    fi
    echo "$name: dmsetup create $map --table '${table:0:60}...'"
    dmsetup create --noudevsync --readonly "$map" --table "$table" || { note_fail "dmsetup $name"; return; }
    MAPS+=("$map")
    # dm-crypt copied the key at table load: drop ours from the (VM-wide) keyring now.
    for kid in "${KEYS[@]}"; do keyctl unlink "$kid" @s >/dev/null; done
    KEYS=()
    dmsetup mknodes "$map"
    mount_ro "/dev/mapper/$map" "/mnt/dm_$target" || { note_fail "mount $name"; return; }
    hashcheck "$target" dmsetup "/mnt/dm_$target" "--export dmsetup table${ref:+ + keyring key from --export masterkey}"
}

dm_via_cryptsetup_script() {   # the generated open.sh, with DEVICE= (or 7:x) adjusted only
    local name=$1 target=${1#gt_} majmin dir=/tmp/cs_$1 script
    attach_ro "$C/${IMAGE[$name]}" || { note_fail "losetup $name"; return; }
    majmin=$(lsblk -dno MAJ:MIN "$LOOP" | tr -d ' ')
    mkdir -p "$dir" && cp "$P/dm_cryptsetup/dmcrypt.$name".* "$dir/"
    script=$dir/dmcrypt.$name.open.sh
    sed -i "s|^DEVICE=.*|DEVICE=$LOOP|" "$script"
    sed -i "s|--table '\(.*\) [0-9]*:[0-9]* \([0-9]*\)'|--table '\1 $majmin \2'|" "$script"
    echo "$name: running generated $(basename "$script") (DEVICE=$LOOP)"
    # dmsetup inside the script waits for udev, which a container lacks: DM_DISABLE_UDEV.
    DM_DISABLE_UDEV=1 timeout 120 sh "$script" || { note_fail "cryptsetup script $name"; return; }
    if grep -q '^cryptsetup open' "$script"; then CRYPTS+=("$name"); else MAPS+=("$name"); fi
    dmsetup mknodes "$name"
    mount_ro "/dev/mapper/$name" "/mnt/cs_$target" || { note_fail "mount $name"; return; }
    hashcheck "$target" cryptsetup-script "/mnt/cs_$target" "--export cryptsetup $(basename "$script")"
}

fscrypt_v1() {   # mount fscrypt.img, add the proven v1 key (filesystem keyring), read v1/
    local mnt=/mnt/fscrypt
    attach_ro "$C/fscrypt.img" || { note_fail "losetup fscrypt"; return; }
    mount_ro "$LOOP" "$mnt" || { note_fail "mount fscrypt"; return; }
    "${PY[@]}" fscrypt-v1 --fscrypt-json "$P/fscrypt/fscrypt.json" --mount "$mnt" \
        || { note_fail "fscrypt v1 add_key"; return; }
    hashcheck fscrypt_v1 kernel-fscrypt "$mnt/v1" "v1 master key via FS_IOC_ADD_ENCRYPTION_KEY"
    "${PY[@]}" fscrypt-v1 --fscrypt-json "$P/fscrypt/fscrypt.json" --mount "$mnt" --remove
}

gocryptfs_fuse() {   # gocryptfs -masterkey with the plugin-proven key, read-only
    local key mnt=/mnt/gocryptfs
    key=$("${PY[@]}" proven-key --rows "$P/gocryptfs/stdout.json") || { note_fail "no proven gocryptfs key"; return; }
    mkdir -p "$mnt"
    gocryptfs -q -nosyslog -ro -masterkey "$key" "$C/gocryptfs_cipher" "$mnt" || { note_fail "gocryptfs mount"; return; }
    MNTS+=("$mnt")
    hashcheck gocryptfs gocryptfs-masterkey "$mnt" "key proven by samples/plugins/memdiver_gocryptfs.py"
}

for name in gt_luks1 gt_luks2 gt_veracrypt; do dm_via_dmsetup "$name"; release; done
for name in gt_luks1 gt_luks2 gt_veracrypt; do dm_via_cryptsetup_script "$name"; release; done
fscrypt_v1; release
if [ -f "$P/gocryptfs/stdout.json" ]; then gocryptfs_fuse; release; else echo "gocryptfs: no plugin output, skipped"; fi
exit $FAILED
