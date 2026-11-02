"""Block-level I/O engine, chained block streams, free-list allocator, and LRU block cache."""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import BinaryIO

from pybindb.constants import (
    BOOTSTRAP_PREFIX_SIZE,
    DEFAULT_BLOCK_SIZE,
    EOF_BLOCK,
)
from pybindb.crypto.hybrid import decrypt_block, encrypt_block
from pybindb.crypto.win_vault import WindowsVaultManager
from pybindb.exceptions import CorruptedDatabaseError
from pybindb.storage.header import DatabaseHeader


class LRUBlockCache:
    """Configurable LRU cache storing decrypted (usable_data, next_block_ptr) by block index."""

    def __init__(self, capacity: int = 256) -> None:
        self.capacity = max(0, capacity)
        self._cache: OrderedDict[int, tuple[bytes, int]] = OrderedDict()

    def get(self, block_index: int) -> tuple[bytes, int] | None:
        if self.capacity <= 0 or block_index not in self._cache:
            return None
        self._cache.move_to_end(block_index)
        return self._cache[block_index]

    def put(self, block_index: int, usable_data: bytes, next_block_ptr: int) -> None:
        if self.capacity <= 0:
            return
        self._cache[block_index] = (usable_data, next_block_ptr)
        self._cache.move_to_end(block_index)
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)

    def invalidate(self, block_index: int) -> None:
        self._cache.pop(block_index, None)

    def clear(self) -> None:
        self._cache.clear()


class BlockIO:
    """Low-level encrypted block reader/writer, chain manager, and free-list allocator."""

    def __init__(
        self,
        file_obj: BinaryIO,
        header: DatabaseHeader,
        manager_key: bytes,
        cache_size: int = 256,
        path: Path | None = None,
    ) -> None:
        self._file = file_obj
        self.header = header
        self._manager_key = manager_key
        self.cache = LRUBlockCache(capacity=cache_size)
        self.path = path

    @classmethod
    def create(
        cls,
        path: str | Path,
        vault_or_key: WindowsVaultManager | bytes,
        header: DatabaseHeader | None = None,
        cache_size: int = 256,
    ) -> BlockIO:
        """Create and initialize a new database file on disk with encrypted Block 0."""
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        mgr_key = (
            vault_or_key.get_or_create_master_key()
            if isinstance(vault_or_key, WindowsVaultManager)
            else bytes(vault_or_key)
        )
        hdr = header if header is not None else DatabaseHeader(block_size=DEFAULT_BLOCK_SIZE)
        hdr.validate()

        f = open(db_path, "w+b")
        instance = cls(
            file_obj=f,
            header=hdr,
            manager_key=mgr_key,
            cache_size=cache_size,
            path=db_path,
        )
        instance.flush_header()
        return instance

    @classmethod
    def open(
        cls,
        path: str | Path,
        vault_or_key: WindowsVaultManager | bytes,
        cache_size: int = 256,
    ) -> BlockIO:
        """Open an existing database file, read the bootstrap prefix, and decrypt Block 0."""
        db_path = Path(path)
        if not db_path.exists():
            raise FileNotFoundError(f"Database file not found: {db_path}")

        mgr_key = (
            vault_or_key.get_or_create_master_key()
            if isinstance(vault_or_key, WindowsVaultManager)
            else bytes(vault_or_key)
        )
        f = open(db_path, "r+b")
        try:
            f.seek(0)
            prefix = f.read(BOOTSTRAP_PREFIX_SIZE)
            _, _, _, block_size = DatabaseHeader.unpack_bootstrap_prefix(prefix)
            f.seek(0)
            raw_block0 = f.read(block_size)
            hdr = DatabaseHeader.from_block0_bytes(raw_block0, mgr_key)
        except Exception:
            f.close()
            raise

        return cls(
            file_obj=f,
            header=hdr,
            manager_key=mgr_key,
            cache_size=cache_size,
            path=db_path,
        )

    @property
    def block_size(self) -> int:
        return self.header.block_size

    @property
    def usable_block_size(self) -> int:
        return self.header.usable_block_size

    def flush_header(self) -> None:
        """Encrypt and write Block 0 (Database Header) to the start of the file."""
        block0 = self.header.to_block0_bytes(self._manager_key)
        self._file.seek(0)
        self._file.write(block0)
        self._file.flush()

    def read_block(self, block_index: int) -> tuple[bytes, int]:
        """Read and decrypt block `block_index` (must be >= 1 and < blocks_total).

        Returns (usable_data, next_block_ptr).
        """
        if block_index < 1 or block_index >= self.header.blocks_total:
            raise CorruptedDatabaseError(
                f"Block index {block_index} out of bounds (blocks_total={self.header.blocks_total})."
            )
        cached = self.cache.get(block_index)
        if cached is not None:
            return cached

        self._file.seek(block_index * self.block_size)
        raw = self._file.read(self.block_size)
        if len(raw) != self.block_size:
            raise CorruptedDatabaseError(
                f"Short read at block {block_index}: expected {self.block_size} bytes, got {len(raw)}."
            )
        usable_data, next_ptr = decrypt_block(
            self._manager_key,
            block_index,
            raw,
            self.block_size,
        )
        self.cache.put(block_index, usable_data, next_ptr)
        return usable_data, next_ptr

    def write_block(
        self,
        block_index: int,
        usable_data: bytes | memoryview,
        next_block_ptr: int = EOF_BLOCK,
    ) -> None:
        """Encrypt and write block `block_index` to disk and update the LRU cache."""
        if block_index < 1:
            raise ValueError("Block index for data/table blocks must be >= 1.")

        U = self.usable_block_size
        raw_usable = bytes(usable_data)
        if len(raw_usable) > U:
            raise ValueError(
                f"usable_data length ({len(raw_usable)}) exceeds usable_block_size ({U})."
            )
        if len(raw_usable) < U:
            raw_usable = raw_usable + b"\x00" * (U - len(raw_usable))

        encrypted = encrypt_block(
            self._manager_key,
            block_index,
            raw_usable,
            next_block_ptr,
            self.block_size,
        )
        self._file.seek(block_index * self.block_size)
        self._file.write(encrypted)
        self.cache.put(block_index, raw_usable, next_block_ptr & 0xFFFFFFFF)

    def allocate_blocks(self, count: int) -> list[int]:
        """Allocate `count` blocks, pulling from `free_block_head` first before appending at EOF."""
        if count <= 0:
            return []

        allocated: list[int] = []
        visited_free: set[int] = set()
        while len(allocated) < count and self.header.free_block_head != EOF_BLOCK:
            free_idx = self.header.free_block_head
            if free_idx in visited_free:
                raise CorruptedDatabaseError(
                    f"Cycle detected in free block list at block {free_idx}."
                )
            visited_free.add(free_idx)
            _, next_free = self.read_block(free_idx)
            self.header.free_block_head = next_free
            allocated.append(free_idx)

        while len(allocated) < count:
            new_idx = self.header.blocks_total
            self.header.blocks_total += 1
            # Initialize newly allocated block placeholder on disk so arbitrary seek/reads work
            self.write_block(new_idx, b"", EOF_BLOCK)
            allocated.append(new_idx)

        return allocated

    def get_chain_blocks(self, start_block: int) -> list[int]:
        """Traverse `next_block_ptr` from `start_block` until `EOF_BLOCK` and return block indices."""
        if start_block == EOF_BLOCK:
            return []
        chain: list[int] = []
        visited: set[int] = set()
        curr = start_block
        while curr != EOF_BLOCK:
            if curr in visited:
                raise CorruptedDatabaseError(
                    f"Cycle detected in block chain at block {curr}."
                )
            visited.add(curr)
            chain.append(curr)
            _, curr = self.read_block(curr)
        return chain

    def free_block_chain(self, start_block: int) -> int:
        """Free a chain of blocks starting at `start_block` onto `header.free_block_head`.

        Links the tail of the freed chain to the previous `free_block_head` and sets
        `header.free_block_head = start_block`. Also scrubs usable data with zeros.
        Returns the number of freed blocks.
        """
        if start_block == EOF_BLOCK:
            return 0

        chain = self.get_chain_blocks(start_block)
        old_free_head = self.header.free_block_head
        for i, blk_idx in enumerate(chain):
            next_ptr = chain[i + 1] if i + 1 < len(chain) else old_free_head
            self.write_block(blk_idx, b"", next_ptr)

        self.header.free_block_head = start_block
        self.flush_header()
        return len(chain)

    def write_stream_to_chain(
        self,
        data: bytes | memoryview,
        start_block: int | None = None,
    ) -> tuple[int, int, int]:
        """Write a contiguous byte stream across chained blocks.

        If `start_block` is provided and not `EOF_BLOCK`, reuses the existing chain in-place,
        allocating extra blocks if `data` grew or freeing tail blocks if `data` shrunk.
        Returns `(start_block, last_block, block_count)`.
        """
        U = self.usable_block_size
        mv = memoryview(data)
        total_len = len(mv)
        needed_blocks = max(1, (total_len + U - 1) // U)

        if start_block is None or start_block == EOF_BLOCK:
            blocks = self.allocate_blocks(needed_blocks)
        else:
            existing = self.get_chain_blocks(start_block)
            if needed_blocks > len(existing):
                extra = self.allocate_blocks(needed_blocks - len(existing))
                blocks = existing + extra
            elif needed_blocks < len(existing):
                blocks = existing[:needed_blocks]
                excess_start = existing[needed_blocks]
                self.free_block_chain(excess_start)
            else:
                blocks = existing

        for i, blk_idx in enumerate(blocks):
            chunk_start = i * U
            chunk_end = min(chunk_start + U, total_len)
            chunk = mv[chunk_start:chunk_end]
            next_ptr = blocks[i + 1] if i + 1 < needed_blocks else EOF_BLOCK
            self.write_block(blk_idx, chunk, next_ptr)

        self.flush_header()
        return blocks[0], blocks[-1], needed_blocks

    def read_stream_from_chain(
        self,
        start_block: int,
        exact_byte_length: int,
    ) -> bytes:
        """Read `exact_byte_length` bytes from the block chain starting at `start_block`.

        Uses a pre-allocated bytearray and zero-copy memoryview slicing.
        """
        if exact_byte_length < 0:
            raise ValueError("exact_byte_length must be >= 0.")
        if exact_byte_length == 0:
            return b""
        if start_block == EOF_BLOCK:
            raise CorruptedDatabaseError(
                f"Cannot read {exact_byte_length} bytes from EOF_BLOCK."
            )

        U = self.usable_block_size
        buf = bytearray(exact_byte_length)
        mv = memoryview(buf)
        offset = 0
        curr = start_block
        visited: set[int] = set()

        while offset < exact_byte_length:
            if curr == EOF_BLOCK:
                raise CorruptedDatabaseError(
                    f"Block chain ended prematurely at {offset}/{exact_byte_length} bytes."
                )
            if curr in visited:
                raise CorruptedDatabaseError(
                    f"Cycle detected in block chain at block {curr}."
                )
            visited.add(curr)
            usable, next_ptr = self.read_block(curr)
            to_copy = min(U, exact_byte_length - offset)
            mv[offset : offset + to_copy] = memoryview(usable)[:to_copy]
            offset += to_copy
            curr = next_ptr

        return bytes(buf)

    def append_to_chain(
        self,
        start_block: int,
        last_block: int,
        current_byte_length: int,
        new_data: bytes | memoryview,
    ) -> tuple[int, int, int]:
        """Append `new_data` to the tail of a stream chain without rewriting prefix blocks.

        Returns `(new_start_block, new_last_block, new_byte_length)`.
        """
        mv_new = memoryview(new_data)
        if len(mv_new) == 0:
            return start_block, last_block, current_byte_length

        if start_block == EOF_BLOCK or current_byte_length == 0:
            s_blk, l_blk, _ = self.write_stream_to_chain(mv_new, start_block=None)
            return s_blk, l_blk, len(mv_new)

        U = self.usable_block_size
        used_in_last = current_byte_length % U

        if used_in_last == 0:
            # last_block is completely full; allocate new blocks and link from last_block
            needed = (len(mv_new) + U - 1) // U
            extra_blocks = self.allocate_blocks(needed)
            last_usable, _ = self.read_block(last_block)
            self.write_block(last_block, last_usable, extra_blocks[0])
            for i, blk_idx in enumerate(extra_blocks):
                c_start = i * U
                c_end = min(c_start + U, len(mv_new))
                next_ptr = extra_blocks[i + 1] if i + 1 < needed else EOF_BLOCK
                self.write_block(blk_idx, mv_new[c_start:c_end], next_ptr)
            self.flush_header()
            return start_block, extra_blocks[-1], current_byte_length + len(mv_new)

        # Fill spare capacity in last_block first
        free_in_last = U - used_in_last
        last_usable, _ = self.read_block(last_block)
        last_buf = bytearray(last_usable)
        first_chunk_len = min(len(mv_new), free_in_last)
        last_buf[used_in_last : used_in_last + first_chunk_len] = mv_new[:first_chunk_len]
        remaining = mv_new[first_chunk_len:]

        if len(remaining) == 0:
            self.write_block(last_block, last_buf, EOF_BLOCK)
            self.flush_header()
            return start_block, last_block, current_byte_length + len(mv_new)

        needed = (len(remaining) + U - 1) // U
        extra_blocks = self.allocate_blocks(needed)
        self.write_block(last_block, last_buf, extra_blocks[0])
        for i, blk_idx in enumerate(extra_blocks):
            c_start = i * U
            c_end = min(c_start + U, len(remaining))
            next_ptr = extra_blocks[i + 1] if i + 1 < needed else EOF_BLOCK
            self.write_block(blk_idx, remaining[c_start:c_end], next_ptr)
        self.flush_header()
        return start_block, extra_blocks[-1], current_byte_length + len(mv_new)

    def update_range_in_chain(
        self,
        start_block: int,
        stream_offset: int,
        patch: bytes | memoryview,
    ) -> None:
        """Update `patch` at `stream_offset` inside the chain starting at `start_block`.

        Re-encrypts ONLY the physical block(s) overlapped by `[stream_offset, stream_offset + len(patch))`.
        """
        mv_patch = memoryview(patch)
        if len(mv_patch) == 0:
            return
        if start_block == EOF_BLOCK or stream_offset < 0:
            raise CorruptedDatabaseError("Invalid start_block or stream_offset for partial update.")

        U = self.usable_block_size
        first_k = stream_offset // U
        last_k = (stream_offset + len(mv_patch) - 1) // U

        curr = start_block
        k = 0
        visited: set[int] = set()
        while k <= last_k:
            if curr == EOF_BLOCK:
                raise CorruptedDatabaseError(
                    f"Block chain ended before reaching target offset {stream_offset}."
                )
            if curr in visited:
                raise CorruptedDatabaseError(f"Cycle detected in block chain at {curr}.")
            visited.add(curr)

            usable, next_ptr = self.read_block(curr)
            if k >= first_k:
                blk_stream_start = k * U
                ov_start = max(stream_offset, blk_stream_start)
                ov_end = min(stream_offset + len(mv_patch), blk_stream_start + U)
                local_start = ov_start - blk_stream_start
                local_end = ov_end - blk_stream_start
                patch_start = ov_start - stream_offset
                patch_end = ov_end - stream_offset

                buf = bytearray(usable)
                buf[local_start:local_end] = mv_patch[patch_start:patch_end]
                self.write_block(curr, buf, next_ptr)

            curr = next_ptr
            k += 1

        self._file.flush()

    def close(self) -> None:
        """Flush header and close the underlying binary file."""
        if not self._file.closed:
            self._file.flush()
            self._file.close()

    def __enter__(self) -> BlockIO:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

