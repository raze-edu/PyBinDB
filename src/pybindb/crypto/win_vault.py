"""Windows Credential Manager (Windows Vault) master key management."""

from __future__ import annotations

import base64
import getpass
import os
from typing import Protocol, runtime_checkable

import keyring

from pybindb.constants import (
    AES_KEY_SIZE,
    DEFAULT_BLOCK_SIZE,
    EOF_BLOCK,
    WIN_VAULT_SERVICE_NAME,
)
from pybindb.crypto.hybrid import decrypt_block as _decrypt_block
from pybindb.crypto.hybrid import encrypt_block as _encrypt_block
from pybindb.exceptions import HardwareKeyError


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for retrieving and storing the 256-bit Manager master key."""

    def get_key(self, service_name: str, username: str) -> bytes | None:
        """Retrieve the 32-byte master key, or None if not found."""
        ...

    def set_key(self, service_name: str, username: str, key: bytes) -> None:
        """Persist the 32-byte master key."""
        ...

    def delete_key(self, service_name: str, username: str) -> None:
        """Delete the stored master key if present."""
        ...


class InMemoryVaultProvider:
    """In-memory KeyProvider implementation for unit testing and isolated environments."""

    def __init__(self, initial_key: bytes | None = None) -> None:
        self._store: dict[tuple[str, str], str] = {}
        self._initial_key = initial_key

    def get_key(self, service_name: str, username: str) -> bytes | None:
        b64_val = self._store.get((service_name, username))
        if b64_val is None:
            if self._initial_key is not None:
                self.set_key(service_name, username, self._initial_key)
                return self._initial_key
            return None
        return base64.b64decode(b64_val.encode("ascii"))

    def set_key(self, service_name: str, username: str, key: bytes) -> None:
        if len(key) != AES_KEY_SIZE:
            raise HardwareKeyError(f"Master key must be {AES_KEY_SIZE} bytes.")
        self._store[(service_name, username)] = base64.b64encode(key).decode("ascii")

    def delete_key(self, service_name: str, username: str) -> None:
        self._store.pop((service_name, username), None)


class WinVaultKeyringProvider:
    """KeyProvider backed by Windows Credential Manager (WinVaultKeyring)."""

    def __init__(self) -> None:
        try:
            from keyring.backends.Windows import WinVaultKeyring

            self._backend: keyring.backend.KeyringBackend = WinVaultKeyring()
        except Exception:
            self._backend = keyring.get_keyring()

    def get_key(self, service_name: str, username: str) -> bytes | None:
        try:
            secret = self._backend.get_password(service_name, username)
            if not secret:
                return None
            raw = base64.b64decode(secret.encode("ascii"))
            if len(raw) != AES_KEY_SIZE:
                raise HardwareKeyError(
                    f"Stored Windows Vault key has invalid length ({len(raw)} != {AES_KEY_SIZE})."
                )
            return raw
        except HardwareKeyError:
            raise
        except Exception as exc:
            raise HardwareKeyError(
                f"Failed to read master key from Windows Credential Manager: {exc}"
            ) from exc

    def set_key(self, service_name: str, username: str, key: bytes) -> None:
        if len(key) != AES_KEY_SIZE:
            raise HardwareKeyError(f"Master key must be {AES_KEY_SIZE} bytes.")
        try:
            b64_secret = base64.b64encode(key).decode("ascii")
            self._backend.set_password(service_name, username, b64_secret)
        except Exception as exc:
            raise HardwareKeyError(
                f"Failed to store master key in Windows Credential Manager: {exc}"
            ) from exc

    def delete_key(self, service_name: str, username: str) -> None:
        try:
            self._backend.delete_password(service_name, username)
        except Exception:
            pass


class WindowsVaultManager:
    """Manages the 256-bit outer block-encryption key via Windows Credential Manager."""

    def __init__(
        self,
        provider: KeyProvider | None = None,
        service_name: str = WIN_VAULT_SERVICE_NAME,
        username: str | None = None,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> None:
        self._provider: KeyProvider = (
            provider if provider is not None else WinVaultKeyringProvider()
        )
        self.service_name = service_name
        self.username = username or getpass.getuser()
        self.block_size = block_size
        self._cached_key: bytes | None = None

    def get_or_create_master_key(self) -> bytes:
        """Retrieve the 32-byte master key from the vault, generating and saving one if absent."""
        if self._cached_key is not None:
            return self._cached_key
        key = self._provider.get_key(self.service_name, self.username)
        if key is None:
            key = os.urandom(AES_KEY_SIZE)
            self._provider.set_key(self.service_name, self.username, key)
        self._cached_key = key
        return key

    def set_master_key(self, key: bytes) -> None:
        """Explicitly set a 32-byte master key in the vault."""
        if len(key) != AES_KEY_SIZE:
            raise HardwareKeyError(f"Master key must be {AES_KEY_SIZE} bytes.")
        self._provider.set_key(self.service_name, self.username, key)
        self._cached_key = key

    def encrypt_block(
        self,
        block_idx: int,
        plaintext: bytes | memoryview,
        next_block_ptr: int = EOF_BLOCK,
        block_size: int | None = None,
    ) -> bytes:
        """Encrypt a block's usable payload and next-block pointer with the Manager key."""
        bsize = block_size if block_size is not None else self.block_size
        key = self.get_or_create_master_key()
        return _encrypt_block(key, block_idx, plaintext, next_block_ptr, bsize)

    def decrypt_block(
        self,
        block_idx: int,
        ciphertext: bytes | memoryview,
        block_size: int | None = None,
    ) -> tuple[bytes, int]:
        """Decrypt a physical block and return (usable_data, next_block_ptr)."""
        bsize = block_size if block_size is not None else self.block_size
        key = self.get_or_create_master_key()
        return _decrypt_block(key, block_idx, ciphertext, bsize)

