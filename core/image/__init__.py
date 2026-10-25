"""Full-memory-image views: ``.mdview`` descriptors and the sources behind them.

A full physical image (LiME, AVML, ELF vmcore, raw, ...) is opened as one of
three *views* — physical, kernel or one process — each described by a small
``.mdview`` file (:mod:`.view_descriptor`) and served as a
:class:`~memdiver.core.dump_source.DumpSource` (:mod:`.sources`). Volatility 3
and pakunoda are imported lazily, only by the code that builds a real layer.
"""
