"""Tests for alignment-based candidate filtering."""

import pytest
from core.alignment_filter import alignment_filter


class TestAlignmentFilter:
    def test_empty_candidates(self):
        assert alignment_filter(set()) == set()

    def test_single_block_full_density(self):
        """32 contiguous candidates at aligned offset pass."""
        candidates = set(range(0x100, 0x100 + 32))
        result = alignment_filter(candidates, block_size=32, alignment=16)
        assert result == candidates

    def test_single_block_below_threshold(self):
        """Only 10/32 bytes — below 75% density — filtered out."""
        candidates = set(range(0x100, 0x100 + 10))
        result = alignment_filter(candidates, block_size=32, alignment=16)
        assert result == set()

    def test_single_block_at_threshold(self):
        """Exactly 24/32 bytes — at 75% threshold — passes."""
        candidates = set(range(0x100, 0x100 + 24))
        result = alignment_filter(candidates, block_size=32, alignment=16)
        assert result == candidates

    def test_scattered_candidates_eliminated(self):
        """Scattered bytes across many blocks: no block reaches density."""
        candidates = {0x100, 0x200, 0x300, 0x400, 0x500}
        result = alignment_filter(candidates, block_size=32, alignment=16)
        assert result == set()

    def test_mixed_dense_and_sparse(self):
        """One dense block + scattered bytes: only dense block survives."""
        dense = set(range(0x1000, 0x1000 + 32))  # full AES key block
        sparse = {0x500, 0x501, 0x502}  # 3 scattered bytes
        candidates = dense | sparse
        result = alignment_filter(candidates, block_size=32, alignment=16)
        assert result == dense

    def test_unaligned_key_still_found(self):
        """Key at 0x1008 (8-byte aligned but not 16-byte): found via nearest block."""
        # With alignment=8, block_start = 0x1008
        candidates = set(range(0x1008, 0x1008 + 32))
        result = alignment_filter(candidates, block_size=32, alignment=8)
        assert result == candidates

    def test_custom_density_threshold(self):
        """Lower threshold 0.5 passes blocks with 16/32 candidates."""
        candidates = set(range(0x100, 0x100 + 16))
        result = alignment_filter(candidates, block_size=32, alignment=16,
                                  density_threshold=0.5)
        assert result == candidates

    def test_realistic_noise_filtered(self):
        """Simulate heap metadata FP: 4 bytes per 32-byte stride."""
        # 16 groups of 4 bytes scattered across 512 bytes
        candidates = set()
        for i in range(16):
            base = 0x500 + i * 32
            candidates.update(range(base, base + 4))
        result = alignment_filter(candidates, block_size=32, alignment=16)
        # 4/32 = 12.5% — way below 75%, all filtered
        assert result == set()

    def test_zero_block_size(self):
        assert alignment_filter({1, 2, 3}, block_size=0) == set()

    def test_zero_alignment(self):
        assert alignment_filter({1, 2, 3}, alignment=0) == set()
