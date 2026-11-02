"""Block 0 Database Header serialization, deserialization, and encryption."""

from __future__ import annotations

from dataclasses import dataclass
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pybindb.constants import (
    AES_KEY_SIZE,
    BLOCK_NONCE_SIZE,
    BLOCK_TAG_SIZE,
    BOOTSTRAP_PREFIX_SIZE,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_ENTITY_ID_LENGTH,
    DEFAULT_ENTITY_NAME_LENGTH,
    DEFAULT_ENTRY_ID_LENGTH,
    DEFAULT_ENTRY_NAME_LENGTH,
    DEFAULT_WRAPPED_KEY_LENGTH,
    EOF_BLOCK,
    FORMAT_VERSION,
    MAGIC_HEX_TAG,
    MIN_BLOCK_SIZE,
    RSA_PUBLIC_KEY_DER_LENGTH,
)
from pybindb.exceptions import BlockAuthenticationError, CorruptedDatabaseError, CryptoError

BOOTSTRAP_STRUCT = struct.Struct("<4sHHI")
HEADER_PAYLOAD_STRUCT = struct.Struct("<IIIIHHHHIIIQIII")


@dataclass
class DatabaseHeader:
    """In-memory representation of Block 0 (Database Header)."""

    block_size: int = DEFAULT_BLOCK_SIZE
    version: int = FORMAT_VERSION
    reserved: int = 0

    blocks_total: int = 1
    free_block_head: int = EOF_BLOCK
    key_length: int = RSA_PUBLIC_KEY_DER_LENGTH
    wrapped_key_length: int = DEFAULT_WRAPPED_KEY_LENGTH

    entity_id_length: int = DEFAULT_ENTITY_ID_LENGTH
    entity_name_length: int = DEFAULT_ENTITY_NAME_LENGTH
    entry_id_length: int = DEFAULT_ENTRY_ID_LENGTH
    entry_name_length: int = DEFAULT_ENTRY_NAME_LENGTH

    entity_table_start: int = EOF_BLOCK
    entity_table_last: int = EOF_BLOCK
    entity_table_count: int = 0
    entity_table_bytes: int = 0

    data_table_start: int = EOF_BLOCK
    data_table_last: int = EOF_BLOCK
    data_table_count: int = 0

    def validate(self) -> None:
        """Validate header invariants."""
        if self.block_size < MIN_BLOCK_SIZE:
            raise CorruptedDatabaseError(
                f"Invalid block_size {self.block_size} (minimum is {MIN_BLOCK_SIZE})."
            )
        if self.version != FORMAT_VERSION:
            raise CorruptedDatabaseError(
                f"Unsupported database format version {self.version} (expected {FORMAT_VERSION})."
            )
        if self.blocks_total < 1:
            raise CorruptedDatabaseError(
                f"Invalid blocks_total {self.blocks_total} (must be >= 1)."
            )

    @property
    def usable_block_size(self) -> int:
        """Return usable payload bytes per data/table block (U = B - 32)."""
        return self.block_size - 32

    @property
    def data_entry_record_size(self) -> int:
        """Return fixed byte size S_data of a single Data Entry Table record."""
        return (
            self.entry_id_length
            + self.entity_id_length
            + self.entry_name_length
            + 1
            + 16
            + 4
            + 4
            + 8
        )

    @property
    def user_entity_record_size(self) -> int:
        """Return fixed byte size S_user of a User Entry record in the Entity Table."""
        return self.entity_id_length + self.entity_name_length + self.key_length + 1

    def pack_bootstrap_prefix(self) -> bytes:
        """Serialize the 12-byte unencrypted bootstrap prefix."""
        return BOOTSTRAP_STRUCT.pack(
            MAGIC_HEX_TAG,
            self.version,
            self.reserved,
            self.block_size,
        )

    @staticmethod
    def unpack_bootstrap_prefix(prefix: bytes | memoryview) -> tuple[bytes, int, int, int]:
        """Unpack and validate the 12-byte unencrypted bootstrap prefix.

        Returns (magic, version, reserved, block_size).
        """
        raw = bytes(prefix)
        if len(raw) < BOOTSTRAP_PREFIX_SIZE:
            raise CorruptedDatabaseError(
                f"Bootstrap prefix too short ({len(raw)} < {BOOTSTRAP_PREFIX_SIZE} bytes)."
            )
        magic, version, reserved, block_size = BOOTSTRAP_STRUCT.unpack(
            raw[:BOOTSTRAP_PREFIX_SIZE]
        )
        if magic != MAGIC_HEX_TAG:
            raise CorruptedDatabaseError(
                f"Invalid database magic bytes {magic!r} (expected {MAGIC_HEX_TAG!r})."
            )
        if version != FORMAT_VERSION:
            raise CorruptedDatabaseError(
                f"Unsupported format version {version} (expected {FORMAT_VERSION})."
            )
        if block_size < MIN_BLOCK_SIZE:
            raise CorruptedDatabaseError(
                f"Invalid block_size {block_size} in bootstrap prefix."
            )
        return magic, version, reserved, block_size

    def pack_payload(self) -> bytes:
        """Serialize the 56-byte header payload fields."""
        return HEADER_PAYLOAD_STRUCT.pack(
            self.blocks_total,
            self.free_block_head,
            self.key_length,
            self.wrapped_key_length,
            self.entity_id_length,
            self.entity_name_length,
            self.entry_id_length,
            self.entry_name_length,
            self.entity_table_start,
            self.entity_table_last,
            self.entity_table_count,
            self.entity_table_bytes,
            self.data_table_start,
            self.data_table_last,
            self.data_table_count,
        )

    def to_block0_bytes(self, manager_key: bytes) -> bytes:
        """Serialize and encrypt Block 0 into an exact `block_size`-byte buffer."""
        self.validate()
        if len(manager_key) != AES_KEY_SIZE:
            raise CryptoError(f"Manager key must be {AES_KEY_SIZE} bytes.")

        prefix = self.pack_bootstrap_prefix()
        payload = self.pack_payload()

        # Total Block 0 size = 12 (prefix) + 12 (nonce) + len(padded_payload) + 16 (tag) = block_size
        padded_payload_len = (
            self.block_size - BOOTSTRAP_PREFIX_SIZE - BLOCK_NONCE_SIZE - BLOCK_TAG_SIZE
        )
        if len(payload) > padded_payload_len:
            raise CorruptedDatabaseError("Block size is too small to fit header payload.")

        padded_payload = payload + b"\x00" * (padded_payload_len - len(payload))
        nonce = os.urandom(BLOCK_NONCE_SIZE)
        aad = prefix + struct.pack("<I", 0)
        ct_and_tag = AESGCM(manager_key).encrypt(nonce, padded_payload, aad)
        block0 = prefix + nonce + ct_and_tag
        assert len(block0) == self.block_size
        return block0

    @classmethod
    def from_block0_bytes(
        cls,
        raw_block0: bytes | memoryview,
        manager_key: bytes,
    ) -> DatabaseHeader:
        """Unpack and decrypt Block 0 using the Manager key."""
        if len(manager_key) != AES_KEY_SIZE:
            raise CryptoError(f"Manager key must be {AES_KEY_SIZE} bytes.")

        raw = bytes(raw_block0)
        _, version, reserved, block_size = cls.unpack_bootstrap_prefix(raw)
        if len(raw) != block_size:
            raise CorruptedDatabaseError(
                f"Block 0 length ({len(raw)}) does not match header block_size ({block_size})."
            )

        prefix = raw[:BOOTSTRAP_PREFIX_SIZE]
        nonce = raw[BOOTSTRAP_PREFIX_SIZE : BOOTSTRAP_PREFIX_SIZE + BLOCK_NONCE_SIZE]
        ct_and_tag = raw[BOOTSTRAP_PREFIX_SIZE + BLOCK_NONCE_SIZE :]
        aad = prefix + struct.pack("<I", 0)

        try:
            padded_payload = AESGCM(manager_key).decrypt(nonce, ct_and_tag, aad)
        except InvalidTag as exc:
            raise BlockAuthenticationError(
                "Block 0 (Database Header) authentication failed: wrong Manager key or tampered header."
            ) from exc

        (
            blocks_total,
            free_block_head,
            key_length,
            wrapped_key_length,
            entity_id_length,
            entity_name_length,
            entry_id_length,
            entry_name_length,
            entity_table_start,
            entity_table_last,
            entity_table_count,
            entity_table_bytes,
            data_table_start,
            data_table_last,
            data_table_count,
        ) = HEADER_PAYLOAD_STRUCT.unpack(padded_payload[: HEADER_PAYLOAD_STRUCT.size])

        header = cls(
            block_size=block_size,
            version=version,
            reserved=reserved,
            blocks_total=blocks_total,
            free_block_head=free_block_head,
            key_length=key_length,
            wrapped_key_length=wrapped_key_length,
            entity_id_length=entity_id_length,
            entity_name_length=entity_name_length,
            entry_id_length=entry_id_length,
            entry_name_length=entry_name_length,
            entity_table_start=entity_table_start,
            entity_table_last=entity_table_last,
            entity_table_count=entity_table_count,
            entity_table_bytes=entity_table_bytes,
            data_table_start=data_table_start,
            data_table_last=data_table_last,
            data_table_count=data_table_count,
        )
        header.validate()
        return header

