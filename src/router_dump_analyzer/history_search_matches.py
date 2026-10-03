"""Immutable exact postings with byte-adaptive storage and bounded select."""

import sys
from array import array
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from operator import index
from typing import SupportsIndex, overload


class MatchSet(Sequence[int]):
    """Sorted ordinals; dense pages never expand the complete match set."""

    __slots__ = ("_bitmap", "_count", "_data", "_prefix", "_universe", "kind", "nbytes")

    def __init__(self, matches: Sequence[int], universe: int) -> None:
        self._count = len(matches)
        self._universe = universe
        self._data = array("I")
        self._bitmap = b""
        width = 4 if universe <= 0xFFFFFFFF else 8
        code = "I" if width == 4 else "Q"
        sparse_bytes = self._count * width
        complement_bytes = (universe - self._count) * width
        bitmap_bytes = ((universe + 255) // 256) * (32 + width)
        if sparse_bytes <= min(complement_bytes, bitmap_bytes):
            self.kind = "sparse"
            self._data = array(code, matches)
        elif complement_bytes <= bitmap_bytes:
            self.kind = "complement"
            omitted = array(code)
            cursor = 0
            for ordinal in matches:
                omitted.extend(range(cursor, ordinal))
                cursor = ordinal + 1
            omitted.extend(range(cursor, universe))
            self._data = omitted
        else:
            self.kind = "bitmap"
            blocks = [0] * ((universe + 255) // 256)
            for ordinal in matches:
                block, bit = divmod(ordinal, 256)
                blocks[block] |= 1 << bit
            # Byte buffers avoid retaining one Python integer for every block.
            self._bitmap = b"".join(block.to_bytes(32, "little") for block in blocks)
            prefix = array(code, [0])
            for block in blocks:
                prefix.append(prefix[-1] + block.bit_count())
            self._prefix = prefix
        self.nbytes: int = sys.getsizeof(self) + sys.getsizeof(self._data)
        if self.kind == "bitmap":
            self.nbytes += sys.getsizeof(self._prefix) + sys.getsizeof(self._bitmap)

    def __len__(self) -> int:
        return self._count

    @overload
    def __getitem__(self, position: SupportsIndex) -> int: ...

    @overload
    def __getitem__(self, position: slice) -> tuple[int, ...]: ...

    def __getitem__(self, position: SupportsIndex | slice) -> int | tuple[int, ...]:
        if isinstance(position, slice):
            return tuple(self[i] for i in range(*position.indices(self._count)))
        position = index(position)
        if position < 0:
            position += self._count
        if not 0 <= position < self._count:
            raise IndexError("match index out of range")
        if self.kind == "sparse":
            return self._data[position]
        if self.kind == "complement":
            low, high = position, min(self._universe - 1, position + len(self._data))
            while low < high:
                middle = (low + high) // 2
                if middle + 1 - bisect_right(self._data, middle) > position:
                    high = middle
                else:
                    low = middle + 1
            return low
        block = bisect_right(self._prefix, position) - 1
        rank = position - self._prefix[block]
        bits = int.from_bytes(self._bitmap[block * 32 : (block + 1) * 32], "little")
        for _ in range(rank):
            bits &= bits - 1
        return block * 256 + (bits & -bits).bit_length() - 1

    def __iter__(self) -> Iterator[int]:
        if self.kind == "sparse":
            yield from self._data
        elif self.kind == "complement":
            cursor = 0
            for omitted in self._data:
                yield from range(cursor, omitted)
                cursor = omitted + 1
            yield from range(cursor, self._universe)
        else:
            for start in range(0, len(self._bitmap), 32):
                bits = int.from_bytes(self._bitmap[start : start + 32], "little")
                while bits:
                    lowest = bits & -bits
                    yield (start // 32) * 256 + lowest.bit_length() - 1
                    bits ^= lowest
