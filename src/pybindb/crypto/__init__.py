"""Cryptographic providers and hybrid encryption helpers for pybindb."""

from pybindb.crypto.hybrid import (
    decrypt_block,
    decrypt_entry_stream,
    encrypt_block,
    encrypt_entry_stream,
    generate_rsa_keypair,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    unwrap_group_private_key,
    wrap_group_private_key,
)
from pybindb.crypto.win_vault import (
    InMemoryVaultProvider,
    KeyProvider,
    WindowsVaultManager,
    WinVaultKeyringProvider,
)
from pybindb.crypto.yubikey import (
    HardwareKeyProvider,
    PivYubiKeyProvider,
    SimulatedYubiKeyProvider,
)

__all__ = [
    "HardwareKeyProvider",
    "InMemoryVaultProvider",
    "KeyProvider",
    "PivYubiKeyProvider",
    "SimulatedYubiKeyProvider",
    "WinVaultKeyringProvider",
    "WindowsVaultManager",
    "decrypt_block",
    "decrypt_entry_stream",
    "encrypt_block",
    "encrypt_entry_stream",
    "generate_rsa_keypair",
    "rsa_oaep_decrypt",
    "rsa_oaep_encrypt",
    "unwrap_group_private_key",
    "wrap_group_private_key",
]

