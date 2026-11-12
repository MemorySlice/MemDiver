"""Volatility 3 plugins for MemDiver ``.msl`` (Memory Slice) process captures.

``msl.info`` summarises the container; ``msl.vasmap`` lists its memory regions. Both need
the primary layer to be an ``MslLayer`` (``vol -p <vol3plugins dir> -f x.msl msl.info``).
Import-time rule of the parent package applies: module level imports stdlib and
``volatility3`` only, MemDiver is imported lazily inside ``run()``.
"""
