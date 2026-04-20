#!/bin/bash
# Build the AES sample process for forensic testing
# Usage: ./build_aes_sample.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cc -O0 -g -o "$DIR/aes_sample" "$DIR/aes_sample.c"
echo "Built: $DIR/aes_sample"
echo "Struct layout:"
echo "  0x00: magic (4B)"
echo "  0x04: key_bits (4B)"
echo "  0x08: algorithm_id (4B)"
echo "  0x0C: block_size (4B)"
echo "  0x10: AES-256 KEY (32B)"
echo "  0x30: IV (16B)"
echo "  0x40: rounds (4B)"
echo "  0x44: initialized (4B)"
echo "  0x48: pad_mode (4B)"
echo "  0x4C: sentinel (4B)"
echo "  0x50: round_keys (240B)"
echo "  Total: $(python3 -c 'print(0x50 + 240)')B"
