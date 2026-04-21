# Key-presence heatmap

:::{admonition} Available in
:class: warning
**Marimo sandbox only** — launch with `memdiver ui` and navigate to the "Key Presence Heatmap" cell.
:::

A matrix with rows = libraries, columns = secret types, and cell intensity encoding "fraction of phases where this secret was recovered". The visual that motivated the IMF study — it makes the "TLS 1.3 missing keys" pattern visible at a glance (BoringSSL zeroes handshake secrets after use; only EXPORTER_SECRET and traffic secrets survive).

Implementation: `ui/views/heatmap.py` → Plotly `Heatmap` figure.
