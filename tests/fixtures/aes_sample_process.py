#!/usr/bin/env python3
"""Sample process with AES-256 key in memory for forensic testing.

Generates a random AES-256 key, pins it in memory, and performs continuous
encryption to keep the key alive. Designed for memory dump analysis testing.

Usage:
    python aes_sample_process.py

Output format (parsed by aes_dump_driver.py):
    MEMDIVER_PID=<pid>
    MEMDIVER_KEY=<hex>
    MEMDIVER_IV=<hex>
    MEMDIVER_READY=1
"""
import ctypes
import os
import signal
import sys
import time

# Flag for clean shutdown
_running = True


def _handle_sigterm(signum, frame):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    # Generate random key and IV
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)

    # Pin in memory via ctypes to prevent GC relocation
    key_buf = ctypes.create_string_buffer(symmetric_key)
    iv_buf = ctypes.create_string_buffer(iv)

    # Output structured info for driver script
    print(f"MEMDIVER_PID={os.getpid()}", flush=True)
    print(f"MEMDIVER_KEY={symmetric_key.hex()}", flush=True)
    print(f"MEMDIVER_IV={iv.hex()}", flush=True)
    print("MEMDIVER_READY=1", flush=True)

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        plaintext = b"This is a secret forensic message."
        # Pad to 48 bytes (multiple of 16 for CBC)
        padded = plaintext + b"\x00" * (48 - len(plaintext))

        while _running:
            encryptor = cipher.encryptor()
            _ = encryptor.update(padded) + encryptor.finalize()
            time.sleep(5)
    except ImportError:
        # If cryptography not installed, just keep key alive
        print("WARNING: cryptography not installed, key held without encryption",
              file=sys.stderr, flush=True)
        while _running:
            # Touch the buffers to prevent optimization
            _ = key_buf.raw + iv_buf.raw
            time.sleep(5)

    # Prevent unused variable optimization
    _ = key_buf.raw + iv_buf.raw


if __name__ == "__main__":
    main()
