"""High-level BinaryDatabase API for managing users, groups, and encrypted data entries."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Sequence

from yubikit.piv import SLOT

from pybindb.constants import (
    DEFAULT_BLOCK_SIZE,
    DEFAULT_ENTITY_ID_LENGTH,
    DEFAULT_ENTITY_NAME_LENGTH,
    DEFAULT_ENTRY_ID_LENGTH,
    DEFAULT_ENTRY_NAME_LENGTH,
    DEFAULT_WRAPPED_KEY_LENGTH,
    RSA_PUBLIC_KEY_DER_LENGTH,
    DataType,
)
from pybindb.crypto.hybrid import (
    decrypt_entry_stream,
    encrypt_entry_stream,
    generate_rsa_keypair,
    rsa_oaep_decrypt,
    unwrap_group_private_key,
    wrap_group_private_key,
)
from pybindb.crypto.win_vault import WindowsVaultManager
from pybindb.crypto.yubikey import HardwareKeyProvider, SimulatedYubiKeyProvider
from pybindb.exceptions import (
    AccessDeniedError,
    DuplicateEntityError,
    EntityNotFoundError,
    EntryNotFoundError,
)
from pybindb.models.entities import (
    EntityRecord,
    GroupEntry,
    GroupMember,
    UserEntry,
    normalize_fixed_id,
)
from pybindb.models.entries import DataEntry
from pybindb.serialization import BinarySerializable, TypeRegistry
from pybindb.storage.block_io import BlockIO
from pybindb.storage.cache import TableIndexCache
from pybindb.storage.header import DatabaseHeader


class BinaryDatabase:
    """High-level manager for a single-file encrypted binary block database (`pybindb`)."""

    def __init__(
        self,
        block_io: BlockIO,
        cache: TableIndexCache,
        vault_manager: WindowsVaultManager | None = None,
        yubikey_provider: HardwareKeyProvider | None = None,
    ) -> None:
        self.block_io = block_io
        self.cache = cache
        self.vault_manager = vault_manager
        self.yubikey_provider: HardwareKeyProvider = (
            yubikey_provider
            if yubikey_provider is not None
            else SimulatedYubiKeyProvider()
        )

    @property
    def header(self) -> DatabaseHeader:
        return self.block_io.header

    @classmethod
    def create(
        cls,
        path: str | Path,
        block_size: int = DEFAULT_BLOCK_SIZE,
        vault_manager: WindowsVaultManager | None = None,
        manager_key: bytes | None = None,
        yubikey_provider: HardwareKeyProvider | None = None,
        entity_id_length: int = DEFAULT_ENTITY_ID_LENGTH,
        entity_name_length: int = DEFAULT_ENTITY_NAME_LENGTH,
        entry_id_length: int = DEFAULT_ENTRY_ID_LENGTH,
        entry_name_length: int = DEFAULT_ENTRY_NAME_LENGTH,
        key_length: int = RSA_PUBLIC_KEY_DER_LENGTH,
        wrapped_key_length: int = DEFAULT_WRAPPED_KEY_LENGTH,
        cache_size: int = 256,
    ) -> BinaryDatabase:
        """Create and initialize a new encrypted binary database file."""
        if vault_manager is None and manager_key is None:
            vault_manager = WindowsVaultManager(block_size=block_size)
        vault_or_key: WindowsVaultManager | bytes = (
            manager_key if manager_key is not None else vault_manager  # type: ignore[assignment]
        )

        hdr = DatabaseHeader(
            block_size=block_size,
            key_length=key_length,
            wrapped_key_length=wrapped_key_length,
            entity_id_length=entity_id_length,
            entity_name_length=entity_name_length,
            entry_id_length=entry_id_length,
            entry_name_length=entry_name_length,
        )
        bio = BlockIO.create(
            path=path,
            vault_or_key=vault_or_key,
            header=hdr,
            cache_size=cache_size,
        )
        return cls(
            block_io=bio,
            cache=TableIndexCache(),
            vault_manager=vault_manager,
            yubikey_provider=yubikey_provider,
        )

    @classmethod
    def open(
        cls,
        path: str | Path,
        vault_manager: WindowsVaultManager | None = None,
        manager_key: bytes | None = None,
        yubikey_provider: HardwareKeyProvider | None = None,
        cache_size: int = 256,
    ) -> BinaryDatabase:
        """Open an existing database file, decrypt Block 0, and populate startup caches."""
        if vault_manager is None and manager_key is None:
            vault_manager = WindowsVaultManager()
        vault_or_key: WindowsVaultManager | bytes = (
            manager_key if manager_key is not None else vault_manager  # type: ignore[assignment]
        )

        bio = BlockIO.open(path=path, vault_or_key=vault_or_key, cache_size=cache_size)
        cache = TableIndexCache.load(bio)
        return cls(
            block_io=bio,
            cache=cache,
            vault_manager=vault_manager,
            yubikey_provider=yubikey_provider,
        )

    def normalize_entity_id(self, entity_id: bytes | str) -> bytes:
        return normalize_fixed_id(entity_id, self.header.entity_id_length)

    def normalize_entry_id(self, entry_id: bytes | str) -> bytes:
        return normalize_fixed_id(entry_id, self.header.entry_id_length)

    def get_entity(self, entity_id: bytes | str) -> EntityRecord:
        eid = self.normalize_entity_id(entity_id)
        entity = self.cache.entities.get(eid)
        if entity is None:
            raise EntityNotFoundError(f"Entity {entity_id!r} not found.")
        return entity

    def get_entry_metadata(self, entry_id: bytes | str) -> DataEntry:
        did = self.normalize_entry_id(entry_id)
        entry = self.cache.data_entries.get(did)
        if entry is None:
            raise EntryNotFoundError(f"Data entry {entry_id!r} not found.")
        return entry

    def _append_entity_record(self, entity: EntityRecord) -> None:
        raw = entity.to_bytes(self.header)
        stream_offset = self.header.entity_table_bytes
        s_blk, l_blk, new_bytes = self.block_io.append_to_chain(
            self.header.entity_table_start,
            self.header.entity_table_last,
            self.header.entity_table_bytes,
            raw,
        )
        self.header.entity_table_start = s_blk
        self.header.entity_table_last = l_blk
        self.header.entity_table_count += 1
        self.header.entity_table_bytes = new_bytes
        self.block_io.flush_header()
        self.cache.entities.register(stream_offset, len(raw), entity)

    def create_user(
        self,
        entity_id: bytes | str,
        name: str,
        yubikey_slot: int | SLOT = SLOT.KEY_MANAGEMENT,
        public_key: bytes | None = None,
    ) -> UserEntry:
        """Create a new UserEntry, generating an RSA-2048 keypair via YubiKey provider if needed."""
        eid = self.normalize_entity_id(entity_id)
        if eid in self.cache.entities:
            raise DuplicateEntityError(f"Entity {entity_id!r} already exists.")

        pub_der = (
            public_key
            if public_key is not None
            else self.yubikey_provider.generate_user_key(entity_id=eid, slot=yubikey_slot)
        )
        user = UserEntry(entity_id=eid, name=name, public_key=pub_der)
        self._append_entity_record(user)
        return user

    def create_group(
        self,
        entity_id: bytes | str,
        name: str,
        member_ids: Sequence[bytes | str],
    ) -> GroupEntry:
        """Create a new GroupEntry and encrypt the group's private key for each member."""
        gid = self.normalize_entity_id(entity_id)
        if gid in self.cache.entities:
            raise DuplicateEntityError(f"Group entity {entity_id!r} already exists.")
        if not member_ids:
            raise ValueError("Group must contain at least one member.")

        canonical_mids = sorted({self.normalize_entity_id(m) for m in member_ids})
        member_entities: list[EntityRecord] = [
            self.get_entity(mid) for mid in canonical_mids
        ]

        group_pub_der, group_priv_der = generate_rsa_keypair()
        members: list[GroupMember] = []
        for member_ent in member_entities:
            wrapped_priv = wrap_group_private_key(
                member_public_key_der=member_ent.public_key,
                group_private_key_der=group_priv_der,
                wrapped_key_length=self.header.wrapped_key_length,
            )
            members.append(
                GroupMember(
                    member_entity_id=member_ent.entity_id,
                    encrypted_group_privkey=wrapped_priv,
                )
            )

        group = GroupEntry(
            entity_id=gid,
            name=name,
            public_key=group_pub_der,
            members=members,
        )
        self._append_entity_record(group)
        return group

    def get_or_create_group(
        self,
        member_ids: Sequence[bytes | str],
        entity_id: bytes | str | None = None,
        name: str | None = None,
    ) -> GroupEntry:
        """Return an existing GroupEntry for the unique member set, or create one automatically."""
        if not member_ids:
            raise ValueError("member_ids cannot be empty.")
        canonical_mids = tuple(sorted({self.normalize_entity_id(m) for m in member_ids}))
        existing = self.cache.entities.find_group_by_members(canonical_mids)
        if existing is not None:
            return existing

        if entity_id is None:
            digest = hashlib.sha256(b"".join(canonical_mids)).digest()
            gid = digest[: self.header.entity_id_length]
            # Ensure no collision with an existing entity ID
            counter = 0
            while gid in self.cache.entities:
                counter += 1
                gid = hashlib.sha256(
                    b"".join(canonical_mids) + counter.to_bytes(4, "little")
                ).digest()[: self.header.entity_id_length]
        else:
            gid = self.normalize_entity_id(entity_id)

        group_name = name or f"auto_grp_{gid[:4].hex()}"
        return self.create_group(
            entity_id=gid,
            name=group_name[: self.header.entity_name_length],
            member_ids=list(canonical_mids),
        )

    def write_entry(
        self,
        entry_id: bytes | str,
        name: str,
        data: bytes | bytearray | memoryview | str | BinarySerializable,
        target_entity_id: bytes | str | Sequence[bytes | str],
        data_type: DataType | None = None,
        type_tag: str = "",
    ) -> DataEntry:
        """Encrypt and write (or update in-place) a Data Entry for a User or Group."""
        did = self.normalize_entry_id(entry_id)
        if all(b == 0 for b in did):
            raise ValueError("entry_id cannot be all-zero (reserved for tombstones).")

        # Resolve target entity (supports automatic group creation when passed a list/tuple/set of member IDs)
        if isinstance(target_entity_id, (list, tuple, set, frozenset)):
            member_list = list(target_entity_id)
            if len(member_list) == 1:
                target_entity = self.get_entity(member_list[0])
            else:
                target_entity = self.get_or_create_group(member_list)
        else:
            target_entity = self.get_entity(target_entity_id)

        # Serialize data and resolve data_type / type_tag
        if isinstance(data, BinarySerializable):
            resolved_type = data_type if data_type is not None else DataType.PYTHON_OBJECT
            resolved_tag = type_tag or data.TYPE_TAG
            raw_payload = data.to_bytes()
        elif isinstance(data, str):
            resolved_type = data_type if data_type is not None else DataType.TEXT
            resolved_tag = type_tag or "utf-8"
            raw_payload = data.encode(resolved_tag)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            resolved_type = data_type if data_type is not None else DataType.RAW
            resolved_tag = type_tag
            raw_payload = bytes(data)
        else:
            raise TypeError(
                f"Unsupported data payload type {type(data).__name__}. "
                "Provide bytes, str, or a BinarySerializable instance."
            )

        encrypted_stream = encrypt_entry_stream(
            public_key_der=target_entity.public_key,
            entry_id=did,
            plaintext=raw_payload,
        )

        existing_cached = self.cache.data_entries.get_cached(did)
        if existing_cached is not None:
            # Update existing DataEntry's block chain in-place
            start_blk, _, blk_count = self.block_io.write_stream_to_chain(
                encrypted_stream,
                start_block=existing_cached.entry.address,
            )
            updated_entry = DataEntry(
                entry_id=did,
                entity_id=target_entity.entity_id,
                name=name,
                data_type=resolved_type,
                type_tag=resolved_tag,
                address=start_blk,
                block_count=blk_count,
                payload_length=len(encrypted_stream),
            )
            self.block_io.update_range_in_chain(
                self.header.data_table_start,
                existing_cached.stream_offset,
                updated_entry.to_bytes(self.header),
            )
            self.cache.data_entries.register(
                existing_cached.record_index,
                existing_cached.stream_offset,
                updated_entry,
            )
            return updated_entry

        # New entry: allocate chain and write payload
        start_blk, _, blk_count = self.block_io.write_stream_to_chain(
            encrypted_stream,
            start_block=None,
        )
        new_entry = DataEntry(
            entry_id=did,
            entity_id=target_entity.entity_id,
            name=name,
            data_type=resolved_type,
            type_tag=resolved_tag,
            address=start_blk,
            block_count=blk_count,
            payload_length=len(encrypted_stream),
        )
        entry_bytes = new_entry.to_bytes(self.header)

        # Reuse tombstone slot if available, otherwise append to Data Entry Table stream
        tombstone_slot = self.cache.data_entries.pop_tombstone_slot()
        if tombstone_slot is not None:
            rec_idx, stream_offset = tombstone_slot
            self.block_io.update_range_in_chain(
                self.header.data_table_start,
                stream_offset,
                entry_bytes,
            )
            self.cache.data_entries.register(rec_idx, stream_offset, new_entry)
            return new_entry

        rec_idx = self.header.data_table_count
        current_table_bytes = rec_idx * self.header.data_entry_record_size
        s_blk, l_blk, _ = self.block_io.append_to_chain(
            self.header.data_table_start,
            self.header.data_table_last,
            current_table_bytes,
            entry_bytes,
        )
        self.header.data_table_start = s_blk
        self.header.data_table_last = l_blk
        self.header.data_table_count += 1
        self.block_io.flush_header()
        self.cache.data_entries.register(rec_idx, current_table_bytes, new_entry)
        return new_entry

    def _resolve_decryptor(
        self,
        owner_entity_id: bytes,
        reader_entity_id: bytes,
        yubikey_slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> Callable[[bytes], bytes]:
        """Resolve an RSA-OAEP decryptor for `owner_entity_id` using `reader_entity_id`'s credentials."""
        reader_entity = self.get_entity(reader_entity_id)
        owner_entity = self.get_entity(owner_entity_id)

        if reader_entity.entity_id == owner_entity.entity_id:
            if isinstance(reader_entity, UserEntry):
                return self.yubikey_provider.get_decryptor(
                    entity_id=reader_entity.entity_id,
                    slot=yubikey_slot,
                )
            raise AccessDeniedError(
                "A Group entity cannot directly authenticate without a User member's hardware key."
            )

        if isinstance(owner_entity, GroupEntry):
            wrapped_blob = owner_entity.get_wrapped_key(reader_entity.entity_id)
            if wrapped_blob is None:
                raise AccessDeniedError(
                    f"Entity {reader_entity.name!r} ({reader_entity.entity_id.hex()}) is not a member "
                    f"of group {owner_entity.name!r} ({owner_entity.entity_id.hex()})."
                )
            member_decryptor = self.yubikey_provider.get_decryptor(
                entity_id=reader_entity.entity_id,
                slot=yubikey_slot,
            )
            group_priv_der = unwrap_group_private_key(
                member_decryptor=member_decryptor,
                wrapped_blob=wrapped_blob,
                wrapped_key_length=self.header.wrapped_key_length,
            )
            return lambda ct: rsa_oaep_decrypt(group_priv_der, ct)

        raise AccessDeniedError(
            f"Entity {reader_entity.name!r} is not authorized to decrypt entry owned by {owner_entity.name!r}."
        )

    def read_entry(
        self,
        entry_id: bytes | str,
        reader_entity_id: bytes | str,
        yubikey_slot: int | SLOT = SLOT.KEY_MANAGEMENT,
        deserialize: bool = True,
    ) -> Any:
        """Read and decrypt a Data Entry using `reader_entity_id` (direct User or Group member)."""
        did = self.normalize_entry_id(entry_id)
        cached = self.cache.data_entries.get_cached(did)
        if cached is None:
            raise EntryNotFoundError(f"Data entry {entry_id!r} not found.")

        entry = cached.entry
        reader_eid = self.normalize_entity_id(reader_entity_id)
        decryptor = self._resolve_decryptor(
            owner_entity_id=entry.entity_id,
            reader_entity_id=reader_eid,
            yubikey_slot=yubikey_slot,
        )

        encrypted_stream = self.block_io.read_stream_from_chain(
            entry.address,
            entry.payload_length,
        )
        plaintext = decrypt_entry_stream(
            private_key_decryptor=decryptor,
            entry_id=entry.entry_id,
            encrypted_stream=encrypted_stream,
        )

        if not deserialize:
            return plaintext

        if entry.data_type == DataType.TEXT:
            encoding = entry.type_tag or "utf-8"
            return plaintext.decode(encoding)
        if entry.data_type == DataType.PYTHON_OBJECT:
            model_cls = TypeRegistry.get(entry.type_tag)
            return model_cls.from_bytes(plaintext)
        return plaintext

    def delete_entry(self, entry_id: bytes | str) -> None:
        """Delete a Data Entry, freeing its block chain onto `free_block_head` and writing a tombstone."""
        did = self.normalize_entry_id(entry_id)
        cached = self.cache.data_entries.remove(did)
        if cached is None:
            raise EntryNotFoundError(f"Data entry {entry_id!r} not found.")

        self.block_io.free_block_chain(cached.entry.address)
        tombstone_bytes = cached.entry.to_tombstone(self.header).to_bytes(self.header)
        self.block_io.update_range_in_chain(
            self.header.data_table_start,
            cached.stream_offset,
            tombstone_bytes,
        )
        self.block_io.flush_header()

    def close(self) -> None:
        """Flush header and close the database file."""
        self.block_io.close()

    def __enter__(self) -> BinaryDatabase:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

