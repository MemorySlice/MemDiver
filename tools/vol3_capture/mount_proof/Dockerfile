# Mount-proof runner image: the tools needed to open the capture-v2 containers
# with keys recovered from the memory image (see ../README.md "Mount proof").
# fscrypt keys are added with the raw FS_IOC_ADD_ENCRYPTION_KEY ioctl (python3),
# because fscryptctl is not packaged for noble.
# Built and driven by ../mount_proof.sh; runs --privileged with -v /dev:/dev.
FROM ubuntu:24.04
ARG APT_PROXY=""
RUN if [ -n "$APT_PROXY" ]; then \
      echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/01proxy; fi \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      cryptsetup-bin dmsetup e2fsprogs xfsprogs dosfstools mtools util-linux \
      gocryptfs fuse3 keyutils python3 python3-cryptography \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/01proxy
