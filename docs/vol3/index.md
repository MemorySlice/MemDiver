---
myst:
  html_meta:
    "description lang=en": "Volatility 3 plugin suite for secrets in memory: dm-crypt/LUKS, WireGuard, keyring, fscrypt, eCryptfs, SSH, a .msl layer and plugin synthesis."
---

# Volatility 3 plugins

A suite of Volatility 3 plugins that recover cryptographic secrets from memory and
**prove** each one with a format-native oracle, plus a synthesis path that turns a key
located in a process slice into a standalone plugin. This is the documentation of the
MemDiver entry to the Volatility 3 Plugin Contest 2026.

Start with the [overview](README.md). The other pages go deeper:

| Page | Read it for |
|---|---|
| [Overview](README.md) | pitch, differentiators, plugin table, install, quick start on the in-repo samples |
| [Usage](USAGE.md) | one section per plugin: options, examples, output columns, exports |
| [Technical details](TECHNICAL_DETAILS.md) | oracle taxonomy, structure walks, proof semantics, honest limits |
| [Plugin synthesis](SYNTHESIS.md) | recipe v2, locators, inlined oracles, the self-test, the seven format kinds |
| [The .msl layer](MSL_LAYER.md) | `vol -f capture.msl`, the slim reader, the `msl.*` plugins |
| [Validation](VALIDATION.md) | every claim ID, what it proves and on which data, `make validate`, the mount proof |
| [Compatibility](COMPATIBILITY.md) | Volatility versions, kernels, paging modes, platforms |
| [Upstream](UPSTREAM.md) | LA57 pull requests #1939 and #1991 and how the stacker relates to them |

```{toctree}
:maxdepth: 2
:hidden:

README
USAGE
TECHNICAL_DETAILS
SYNTHESIS
MSL_LAYER
VALIDATION
COMPATIBILITY
UPSTREAM
```
