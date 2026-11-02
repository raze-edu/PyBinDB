"""Constants and enumerations for pybindb binary format."""

from enum import IntEnum

# Header & Block Constants
MAGIC_HEX_TAG: bytes = b"BDB1"
FORMAT_VERSION: int = 1
EOF_BLOCK: int = 0xFFFFFFFF

# Entity Flags
USER_FLAG_SET: int = 0x01
USER_FLAG_GROUP: int = 0x00

# Block Sizing & Overhead
MIN_BLOCK_SIZE: int = 512
DEFAULT_BLOCK_SIZE: int = 4096

BOOTSTRAP_PREFIX_SIZE: int = 12
BLOCK_NONCE_SIZE: int = 12
BLOCK_TAG_SIZE: int = 16
BLOCK_PTR_SIZE: int = 4
BLOCK_CRYPTO_OVERHEAD: int = BLOCK_NONCE_SIZE + BLOCK_TAG_SIZE  # 28 bytes
BLOCK_OVERHEAD: int = BLOCK_CRYPTO_OVERHEAD + BLOCK_PTR_SIZE    # 32 bytes

# Cryptographic Key Lengths (RSA-2048 + AES-256-GCM)
AES_KEY_SIZE: int = 32
RSA_KEY_BITS: int = 2048
RSA_PUBLIC_KEY_DER_LENGTH: int = 294
RSA_OAEP_CIPHERTEXT_LENGTH: int = 256
PADDED_PRIVATE_KEY_LENGTH: int = 1252
DEFAULT_WRAPPED_KEY_LENGTH: int = (
    RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE + BLOCK_TAG_SIZE + PADDED_PRIVATE_KEY_LENGTH
)  # 1536 bytes

# Entry Stream Encryption Framing
ENTRY_STREAM_HEADER_SIZE: int = (
    RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE + BLOCK_TAG_SIZE
)  # 284 bytes

# Default Field Lengths
DEFAULT_ENTITY_ID_LENGTH: int = 16
DEFAULT_ENTITY_NAME_LENGTH: int = 64
DEFAULT_ENTRY_ID_LENGTH: int = 16
DEFAULT_ENTRY_NAME_LENGTH: int = 64
TYPE_TAG_LENGTH: int = 16

# Windows Credential Manager Defaults
WIN_VAULT_SERVICE_NAME: str = "pybindb_manager"


class DataType(IntEnum):
    """Supported data entry types in the Data Entry Table."""

    RAW = 1
    TEXT = 2
    IMAGE = 3
    AUDIO = 4
    PYTHON_OBJECT = 5

