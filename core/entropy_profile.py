"""Compact, array-backed sliding-window entropy profile.

``compute_entropy_profile`` used to return ``list(zip(offsets, entropies))``:
one Python tuple + int + float per window position, roughly 120 bytes each.
On a step-1 scan of a multi-hundred-MB dump that is tens of GB of objects.

:class:`EntropyProfile` keeps the same data in two numpy arrays (16 bytes per
position) while still behaving as a read-only sequence of ``(int, float)``
tuples, so every existing consumer (``for off, ent in profile``,
``profile[i][1]``, ``profile[-1][0]``, ``len(profile)``, ``if not profile``,
``profile == [...]``) keeps working unchanged and sees plain Python scalars --
which keeps JSON serialisation of derived payloads byte-identical. Hot
consumers can skip the per-item boxing via :meth:`EntropyProfile.as_arrays`.
"""

from collections.abc import Sequence
from typing import Iterator, List, Tuple

import numpy as np

# Positions boxed per ``tolist()`` batch while iterating. Keeps iteration fast
# (C-level conversion) without materialising the whole profile as objects.
_ITER_CHUNK = 1 << 16


def _readonly(array: np.ndarray, dtype) -> np.ndarray:
    result = np.ascontiguousarray(array, dtype=dtype)
    if result is array:
        result = result.view()
    result.flags.writeable = False
    return result


class EntropyProfile(Sequence):
    """Read-only sequence of ``(offset, entropy)`` pairs backed by numpy arrays.

    Attributes:
        offsets: ``int64`` window start offsets, ascending.
        values: ``float64`` Shannon entropy (bits/byte) per window.
    """

    __slots__ = ("offsets", "values")
    __hash__ = None  # mutable-sequence-like equality semantics, like list

    def __init__(self, offsets: np.ndarray, values: np.ndarray) -> None:
        offsets = _readonly(offsets, np.int64)
        values = _readonly(values, np.float64)
        if offsets.ndim != 1 or offsets.shape != values.shape:
            raise ValueError("offsets and values must be 1-D arrays of equal length")
        self.offsets = offsets
        self.values = values

    @classmethod
    def empty(cls) -> "EntropyProfile":
        return cls(np.empty(0, dtype=np.int64), np.empty(0, dtype=np.float64))

    @classmethod
    def from_pairs(cls, pairs) -> "EntropyProfile":
        """Build from any iterable of ``(offset, entropy)`` pairs."""
        if isinstance(pairs, EntropyProfile):
            return pairs
        pairs = list(pairs)
        offsets = np.fromiter((p[0] for p in pairs), dtype=np.int64, count=len(pairs))
        values = np.fromiter((p[1] for p in pairs), dtype=np.float64, count=len(pairs))
        return cls(offsets, values)

    def as_arrays(self) -> Tuple[np.ndarray, np.ndarray]:
        """Return the (read-only) ``(offsets, values)`` arrays without copying."""
        return self.offsets, self.values

    def tolist(self) -> List[Tuple[int, float]]:
        """Materialise the legacy ``list[tuple[int, float]]`` representation."""
        return list(zip(self.offsets.tolist(), self.values.tolist()))

    def __len__(self) -> int:
        return int(self.offsets.shape[0])

    def __bool__(self) -> bool:
        return self.offsets.shape[0] > 0

    def __getitem__(self, index):
        if isinstance(index, slice):
            return EntropyProfile(self.offsets[index], self.values[index])
        # numpy handles negative indices and raises IndexError when out of range.
        return (int(self.offsets[index]), float(self.values[index]))

    def __iter__(self) -> Iterator[Tuple[int, float]]:
        total = len(self)
        for start in range(0, total, _ITER_CHUNK):
            stop = start + _ITER_CHUNK
            yield from zip(
                self.offsets[start:stop].tolist(), self.values[start:stop].tolist()
            )

    def __eq__(self, other) -> bool:
        if isinstance(other, EntropyProfile):
            return bool(
                np.array_equal(self.offsets, other.offsets)
                and np.array_equal(self.values, other.values)
            )
        if isinstance(other, (list, tuple)):
            # Same semantics as the old ``list`` return value: element-wise
            # tuple equality (a list of lists does not equal a list of tuples).
            return len(other) == len(self) and all(
                mine == theirs for mine, theirs in zip(self, other)
            )
        return NotImplemented

    def __repr__(self) -> str:
        preview = ", ".join(repr(p) for p in self[:3])
        more = ", ..." if len(self) > 3 else ""
        return f"EntropyProfile([{preview}{more}], len={len(self)})"

    def __reduce__(self):
        return (EntropyProfile, (np.array(self.offsets), np.array(self.values)))
