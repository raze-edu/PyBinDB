"""In-memory Entity Table and Data Entry Table startup offset caches."""

from __future__ import annotations

from dataclasses import dataclass

from pybindb.constants import EOF_BLOCK
from pybindb.exceptions import CorruptedDatabaseError
from pybindb.models.entities import (
    EntityRecord,
    GroupEntry,
    UserEntry,
    parse_entity_from_stream,
)
from pybindb.models.entries import DataEntry
from pybindb.storage.block_io import BlockIO
from pybindb.storage.header import DatabaseHeader


@dataclass
class CachedEntity:
    """Cached Entity record metadata for O(1) lookup and targeted in-place updates."""

    stream_offset: int
    byte_length: int
    entity: EntityRecord


@dataclass
class CachedDataEntry:
    """Cached Data Entry record metadata for O(1) lookup and targeted in-place updates."""

    record_index: int
    stream_offset: int
    entry: DataEntry


class EntityCache:
    """In-memory index of variable-length User and Group records from the Entity Table."""

    def __init__(self) -> None:
        self._by_id: dict[bytes, CachedEntity] = {}
        self._group_by_members: dict[tuple[bytes, ...], GroupEntry] = {}

    def clear(self) -> None:
        self._by_id.clear()
        self._group_by_members.clear()

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, entity_id: bytes) -> bool:
        return bytes(entity_id) in self._by_id

    def get_cached(self, entity_id: bytes) -> CachedEntity | None:
        return self._by_id.get(bytes(entity_id))

    def get(self, entity_id: bytes) -> EntityRecord | None:
        cached = self._by_id.get(bytes(entity_id))
        return cached.entity if cached is not None else None

    def find_group_by_members(self, member_ids: list[bytes] | tuple[bytes, ...]) -> GroupEntry | None:
        """Look up an existing GroupEntry by its canonical sorted tuple of unique member IDs."""
        canonical = tuple(sorted({bytes(mid) for mid in member_ids}))
        return self._group_by_members.get(canonical)

    def register(
        self,
        stream_offset: int,
        byte_length: int,
        entity: EntityRecord,
    ) -> CachedEntity:
        cached = CachedEntity(
            stream_offset=stream_offset,
            byte_length=byte_length,
            entity=entity,
        )
        self._by_id[entity.entity_id] = cached
        if isinstance(entity, GroupEntry):
            self._group_by_members[entity.canonical_member_ids] = entity
        return cached

    def all_entities(self) -> list[EntityRecord]:
        return [c.entity for c in self._by_id.values()]

    def all_users(self) -> list[UserEntry]:
        return [c.entity for c in self._by_id.values() if isinstance(c.entity, UserEntry)]

    def all_groups(self) -> list[GroupEntry]:
        return [c.entity for c in self._by_id.values() if isinstance(c.entity, GroupEntry)]

    @classmethod
    def from_stream(
        cls,
        stream: bytes | memoryview,
        header: DatabaseHeader,
    ) -> EntityCache:
        """Scan the contiguous Entity Table byte stream once and populate the cache."""
        cache = cls()
        mv = memoryview(stream)
        offset = 0
        count = 0
        while offset < len(mv) and count < header.entity_table_count:
            entity, record_len = parse_entity_from_stream(mv, offset, header)
            cache.register(offset, record_len, entity)
            offset += record_len
            count += 1

        if count != header.entity_table_count:
            raise CorruptedDatabaseError(
                f"Entity Table count mismatch: parsed {count}, header expected {header.entity_table_count}."
            )
        return cache

    @classmethod
    def load(cls, block_io: BlockIO) -> EntityCache:
        """Load the Entity Table chain from `block_io` and build the `EntityCache`."""
        hdr = block_io.header
        if (
            hdr.entity_table_start == EOF_BLOCK
            or hdr.entity_table_count == 0
            or hdr.entity_table_bytes == 0
        ):
            return cls()
        stream = block_io.read_stream_from_chain(
            hdr.entity_table_start,
            hdr.entity_table_bytes,
        )
        return cls.from_stream(stream, hdr)


class DataEntryCache:
    """In-memory index of fixed-size DataEntry records from the Data Entry Table."""

    def __init__(self) -> None:
        self._by_id: dict[bytes, CachedDataEntry] = {}
        self._tombstone_slots: list[tuple[int, int]] = []

    def clear(self) -> None:
        self._by_id.clear()
        self._tombstone_slots.clear()

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, entry_id: bytes) -> bool:
        return bytes(entry_id) in self._by_id

    def get_cached(self, entry_id: bytes) -> CachedDataEntry | None:
        return self._by_id.get(bytes(entry_id))

    def get(self, entry_id: bytes) -> DataEntry | None:
        cached = self._by_id.get(bytes(entry_id))
        return cached.entry if cached is not None else None

    def register(
        self,
        record_index: int,
        stream_offset: int,
        entry: DataEntry,
    ) -> CachedDataEntry:
        cached = CachedDataEntry(
            record_index=record_index,
            stream_offset=stream_offset,
            entry=entry,
        )
        self._by_id[entry.entry_id] = cached
        return cached

    def pop_tombstone_slot(self) -> tuple[int, int] | None:
        """Pop a reusable `(record_index, stream_offset)` slot from a previously deleted entry."""
        if self._tombstone_slots:
            return self._tombstone_slots.pop()
        return None

    def remove(self, entry_id: bytes) -> CachedDataEntry | None:
        """Remove an entry from the active index and record its slot for reuse."""
        cached = self._by_id.pop(bytes(entry_id), None)
        if cached is not None:
            self._tombstone_slots.append((cached.record_index, cached.stream_offset))
        return cached

    def all_entries(self) -> list[DataEntry]:
        return [c.entry for c in self._by_id.values()]

    @classmethod
    def from_stream(
        cls,
        stream: bytes | memoryview,
        header: DatabaseHeader,
    ) -> DataEntryCache:
        """Scan the contiguous Data Entry Table byte stream once and populate the cache."""
        cache = cls()
        mv = memoryview(stream)
        rec_size = header.data_entry_record_size
        total_records = header.data_table_count

        if len(mv) < total_records * rec_size:
            raise CorruptedDatabaseError(
                f"Data Entry Table stream too short ({len(mv)} < {total_records * rec_size})."
            )

        for idx in range(total_records):
            offset = idx * rec_size
            entry = DataEntry.from_bytes(mv[offset : offset + rec_size], header)
            if entry.is_deleted:
                cache._tombstone_slots.append((idx, offset))
            else:
                cache.register(idx, offset, entry)

        return cache

    @classmethod
    def load(cls, block_io: BlockIO) -> DataEntryCache:
        """Load the Data Entry Table chain from `block_io` and build the `DataEntryCache`."""
        hdr = block_io.header
        if hdr.data_table_start == EOF_BLOCK or hdr.data_table_count == 0:
            return cls()
        total_bytes = hdr.data_table_count * hdr.data_entry_record_size
        stream = block_io.read_stream_from_chain(hdr.data_table_start, total_bytes)
        return cls.from_stream(stream, hdr)


class TableIndexCache:
    """Combined startup cache holding both `EntityCache` and `DataEntryCache`."""

    def __init__(
        self,
        entities: EntityCache | None = None,
        data_entries: DataEntryCache | None = None,
    ) -> None:
        self.entities = entities if entities is not None else EntityCache()
        self.data_entries = data_entries if data_entries is not None else DataEntryCache()

    @classmethod
    def load(cls, block_io: BlockIO) -> TableIndexCache:
        return cls(
            entities=EntityCache.load(block_io),
            data_entries=DataEntryCache.load(block_io),
        )

