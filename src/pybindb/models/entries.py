"""Data Entry Table record model and packing/unpacking."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import TYPE_CHECKING

from pybindb.constants import EOF_BLOCK, TYPE_TAG_LENGTH, DataType
from pybindb.exceptions import CorruptedDatabaseError
from pybindb.models.entities import (
    decode_fixed_string,
    encode_fixed_string,
    normalize_fixed_id,
)

if TYPE_CHECKING:
    from pybindb.storage.header import DatabaseHeader

DATA_ENTRY_TAIL_STRUCT = struct.Struct("<B16sIIQ")


@dataclass
class DataEntry:
    """Fixed-size record in the Data Entry Table."""

    entry_id: bytes
    entity_id: bytes
    name: str
    data_type: DataType
    type_tag: str
    address: int
    block_count: int
    payload_length: int

    @property
    def is_deleted(self) -> bool:
        """A tombstone record has all-zero entry_id bytes."""
        return all(b == 0 for b in self.entry_id)

    def to_tombstone(self, header: DatabaseHeader) -> DataEntry:
        """Return a zeroed tombstone copy of this DataEntry."""
        return DataEntry(
            entry_id=b"\x00" * header.entry_id_length,
            entity_id=b"\x00" * header.entity_id_length,
            name="",
            data_type=DataType.RAW,
            type_tag="",
            address=EOF_BLOCK,
            block_count=0,
            payload_length=0,
        )

    def to_bytes(self, header: DatabaseHeader) -> bytes:
        """Serialize this DataEntry into an exact `header.data_entry_record_size`-byte buffer."""
        did = normalize_fixed_id(self.entry_id, header.entry_id_length)
        eid = normalize_fixed_id(self.entity_id, header.entity_id_length)
        dname = encode_fixed_string(self.name, header.entry_name_length)
        tag_bytes = encode_fixed_string(self.type_tag, TYPE_TAG_LENGTH)
        tail = DATA_ENTRY_TAIL_STRUCT.pack(
            int(self.data_type),
            tag_bytes,
            self.address & 0xFFFFFFFF,
            self.block_count & 0xFFFFFFFF,
            self.payload_length,
        )
        return did + eid + dname + tail

    @classmethod
    def from_bytes(
        cls,
        raw: bytes | memoryview,
        header: DatabaseHeader,
    ) -> DataEntry:
        """Deserialize a single DataEntry from `header.data_entry_record_size` bytes."""
        mv = memoryview(raw)
        expected_len = header.data_entry_record_size
        if len(mv) != expected_len:
            raise CorruptedDatabaseError(
                f"Invalid DataEntry byte length ({len(mv)} != {expected_len})."
            )

        L_did = header.entry_id_length
        L_eid = header.entity_id_length
        L_dname = header.entry_name_length

        pos = 0
        entry_id = bytes(mv[pos : pos + L_did])
        pos += L_did
        entity_id = bytes(mv[pos : pos + L_eid])
        pos += L_eid
        name = decode_fixed_string(mv[pos : pos + L_dname])
        pos += L_dname

        dtype_int, tag_raw, address, block_count, payload_length = (
            DATA_ENTRY_TAIL_STRUCT.unpack(mv[pos:])
        )
        try:
            dtype = DataType(dtype_int)
        except ValueError:
            dtype = DataType.RAW

        return cls(
            entry_id=entry_id,
            entity_id=entity_id,
            name=name,
            data_type=dtype,
            type_tag=decode_fixed_string(tag_raw),
            address=address,
            block_count=block_count,
            payload_length=payload_length,
        )
