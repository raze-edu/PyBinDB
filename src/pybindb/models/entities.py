"""Entity Table data models: UserEntry, GroupEntry, GroupMember, and TableDescriptor."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import TYPE_CHECKING, TypeAlias

from pybindb.constants import USER_FLAG_GROUP, USER_FLAG_SET
from pybindb.exceptions import CorruptedDatabaseError

if TYPE_CHECKING:
    from pybindb.storage.header import DatabaseHeader


def normalize_fixed_id(raw_id: bytes | str, length: int) -> bytes:
    """Convert a string or bytes ID into an exact `length`-byte zero-padded identifier."""
    if isinstance(raw_id, str):
        encoded = raw_id.encode("utf-8")
    else:
        encoded = bytes(raw_id)
    if len(encoded) > length:
        raise ValueError(f"ID {raw_id!r} exceeds configured byte length ({length}).")
    return encoded.ljust(length, b"\x00")


def encode_fixed_string(text: str, length: int) -> bytes:
    """Encode a UTF-8 string into an exact `length`-byte null-padded field."""
    encoded = text.encode("utf-8")
    if len(encoded) > length:
        raise ValueError(f"String {text!r} exceeds configured byte length ({length}).")
    return encoded.ljust(length, b"\x00")


def decode_fixed_string(raw: bytes | memoryview) -> str:
    """Decode a null-padded UTF-8 string field."""
    return bytes(raw).rstrip(b"\x00").decode("utf-8", errors="replace")


@dataclass(frozen=True)
class TableDescriptor:
    """Metadata descriptor for a table block chain."""

    start_block: int
    last_block: int
    number_of_entries: int
    active_bytes: int = 0


@dataclass
class GroupMember:
    """Single member record inside a GroupEntry: (member_entity_id, encrypted_group_privkey)."""

    member_entity_id: bytes
    encrypted_group_privkey: bytes


@dataclass
class UserEntry:
    """Fixed-size User record in the Entity Table (user_flag = 0x01)."""

    entity_id: bytes
    name: str
    public_key: bytes
    user_flag: int = USER_FLAG_SET

    @property
    def is_user(self) -> bool:
        return True

    @property
    def is_group(self) -> bool:
        return False

    def byte_size(self, header: DatabaseHeader) -> int:
        return header.user_entity_record_size

    def to_bytes(self, header: DatabaseHeader) -> bytes:
        eid = normalize_fixed_id(self.entity_id, header.entity_id_length)
        ename = encode_fixed_string(self.name, header.entity_name_length)
        if len(self.public_key) != header.key_length:
            raise ValueError(
                f"User public_key length ({len(self.public_key)}) != header.key_length ({header.key_length})."
            )
        return eid + ename + self.public_key + struct.pack("<B", USER_FLAG_SET)


@dataclass
class GroupEntry:
    """Variable-size Group record in the Entity Table (user_flag = 0x00)."""

    entity_id: bytes
    name: str
    public_key: bytes
    members: list[GroupMember] = field(default_factory=list)
    user_flag: int = USER_FLAG_GROUP

    @property
    def is_user(self) -> bool:
        return False

    @property
    def is_group(self) -> bool:
        return True

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def canonical_member_ids(self) -> tuple[bytes, ...]:
        """Return sorted tuple of unique member entity IDs for O(1) group deduplication."""
        return tuple(sorted({m.member_entity_id for m in self.members}))

    def get_wrapped_key(self, member_entity_id: bytes) -> bytes | None:
        """Return the encrypted group private key blob for `member_entity_id`, or None."""
        for m in self.members:
            if m.member_entity_id == member_entity_id:
                return m.encrypted_group_privkey
        return None

    def byte_size(self, header: DatabaseHeader) -> int:
        base = header.user_entity_record_size
        member_pair_size = header.entity_id_length + header.wrapped_key_length
        return base + 4 + len(self.members) * member_pair_size

    def to_bytes(self, header: DatabaseHeader) -> bytes:
        eid = normalize_fixed_id(self.entity_id, header.entity_id_length)
        ename = encode_fixed_string(self.name, header.entity_name_length)
        if len(self.public_key) != header.key_length:
            raise ValueError(
                f"Group public_key length ({len(self.public_key)}) != header.key_length ({header.key_length})."
            )
        parts = [
            eid,
            ename,
            self.public_key,
            struct.pack("<BI", USER_FLAG_GROUP, len(self.members)),
        ]
        for member in self.members:
            mid = normalize_fixed_id(member.member_entity_id, header.entity_id_length)
            if len(member.encrypted_group_privkey) != header.wrapped_key_length:
                raise ValueError(
                    f"Encrypted group private key length ({len(member.encrypted_group_privkey)}) "
                    f"!= header.wrapped_key_length ({header.wrapped_key_length})."
                )
            parts.append(mid)
            parts.append(member.encrypted_group_privkey)
        return b"".join(parts)


EntityRecord: TypeAlias = UserEntry | GroupEntry


def parse_entity_from_stream(
    stream: bytes | memoryview,
    offset: int,
    header: DatabaseHeader,
) -> tuple[EntityRecord, int]:
    """Parse a single UserEntry or GroupEntry at `offset` in the Entity Table stream.

    Returns `(entity_record, record_byte_length)`.
    """
    mv = memoryview(stream)
    L_eid = header.entity_id_length
    L_ename = header.entity_name_length
    K_len = header.key_length
    W_len = header.wrapped_key_length

    base_len = L_eid + L_ename + K_len + 1
    if offset + base_len > len(mv):
        raise CorruptedDatabaseError(
            f"Truncated Entity record at stream offset {offset} "
            f"(need {base_len} bytes, available {len(mv) - offset})."
        )

    pos = offset
    entity_id = bytes(mv[pos : pos + L_eid])
    pos += L_eid
    name = decode_fixed_string(mv[pos : pos + L_ename])
    pos += L_ename
    public_key = bytes(mv[pos : pos + K_len])
    pos += K_len
    (user_flag,) = struct.unpack("<B", mv[pos : pos + 1])
    pos += 1

    if user_flag == USER_FLAG_SET:
        return (
            UserEntry(
                entity_id=entity_id,
                name=name,
                public_key=public_key,
                user_flag=USER_FLAG_SET,
            ),
            base_len,
        )

    if user_flag != USER_FLAG_GROUP:
        raise CorruptedDatabaseError(
            f"Invalid user_flag 0x{user_flag:02x} at Entity Table offset {offset}."
        )

    if pos + 4 > len(mv):
        raise CorruptedDatabaseError(
            f"Truncated GroupEntry member_count at stream offset {offset}."
        )
    (member_count,) = struct.unpack("<I", mv[pos : pos + 4])
    pos += 4

    pair_len = L_eid + W_len
    total_len = base_len + 4 + member_count * pair_len
    if offset + total_len > len(mv):
        raise CorruptedDatabaseError(
            f"Truncated GroupEntry members array at stream offset {offset} "
            f"(member_count={member_count}, need {total_len} bytes)."
        )

    members: list[GroupMember] = []
    for _ in range(member_count):
        mid = bytes(mv[pos : pos + L_eid])
        pos += L_eid
        wkey = bytes(mv[pos : pos + W_len])
        pos += W_len
        members.append(GroupMember(member_entity_id=mid, encrypted_group_privkey=wkey))

    return (
        GroupEntry(
            entity_id=entity_id,
            name=name,
            public_key=public_key,
            members=members,
            user_flag=USER_FLAG_GROUP,
        ),
        total_len,
    )
