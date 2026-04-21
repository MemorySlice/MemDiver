# Oracle Examples

Ready-to-copy templates demonstrating the two oracle shapes documented in [](interface.md). Save these under your project's `oracles/` directory, edit the marked constants, and point the MemDiver brute-force / n-sweep runners at them.

## `generic_aes_gcm.py` — stateless AES-GCM

```{literalinclude} examples/generic_aes_gcm.py
:language: python
:linenos:
```

## `gocryptfs.py` — stateful factory, HKDF-SHA256 + per-block AEAD

```{literalinclude} examples/gocryptfs.py
:language: python
:linenos:
```

## `tls13_stub.py` — TLS 1.3 traffic-secret verification scaffold

```{literalinclude} examples/tls13_stub.py
:language: python
:linenos:
```
