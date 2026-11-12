Real filesystem heads for tests/test_vol3plugins_secrets_fsmagic.py (made 2026-11-12).

Each image was a sparse `truncate -s <size>` file in an alpine:3.20 container (--privileged
for losetup); the first 4 KiB was kept with `dd bs=4096 count=1` and the image deleted.
Tools: e2fsprogs 1.47.0, xfsprogs 6.8.0, dosfstools 4.2, mkntfs (ntfs-3g 2026.2.25),
btrfs-progs 6.8.1, sgdisk 1.0.10, LVM 2.03.23, util-linux 2.40.1 (mkswap).

  ext4_csum     512M  mkfs.ext4 -F                         (4 KiB blocks, metadata_csum)
  ext4_nocsum   512M  mkfs.ext4 -F -O ^metadata_csum       (4 KiB blocks)
  ext4_1k        64M  mkfs.ext4 -F -b 1024 -O ^metadata_csum (s_first_data_block = 1)
  xfs_v5        320M  mkfs.xfs -f                          (v5, crc=1)
  vfat16         64M  mkfs.vfat -F 16
  vfat32         64M  mkfs.vfat -F 32
  ntfs           64M  mkfs.ntfs -F -Q
  swap           64M  mkswap
  gpt            64M  sgdisk -n 1:2048:0
  lvm2           64M  losetup -f --show; pvcreate -ff -y <loop>   (label in sector 1)
  btrfs         128M  mkfs.btrfs -f ; btrfs.sb64k.bin = bytes [0x10000, 0x11000)
