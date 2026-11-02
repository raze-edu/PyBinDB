"""Custom exception hierarchy for pybindb."""


class PyBinDBError(Exception):
    """Base exception for all pybindb errors."""


class CryptoError(PyBinDBError):
    """Raised when encryption, decryption, or authentication fails."""


class BlockAuthenticationError(CryptoError):
    """Raised when block-level AES-GCM authentication (including AAD block index) fails."""


class EntryAuthenticationError(CryptoError):
    """Raised when entry-level AES-GCM or RSA-OAEP decryption fails."""


class AccessDeniedError(CryptoError):
    """Raised when an entity does not have permission or key material to decrypt an entry."""


class HardwareKeyError(CryptoError):
    """Raised when a YubiKey PIV or Windows Vault operation fails."""


class CorruptedDatabaseError(PyBinDBError):
    """Raised when header magic, version, or block chain integrity is invalid."""


class EntityNotFoundError(PyBinDBError):
    """Raised when a requested User or Group entity ID does not exist."""


class DuplicateEntityError(PyBinDBError):
    """Raised when attempting to create an entity with an ID that already exists."""


class EntryNotFoundError(PyBinDBError):
    """Raised when a requested Data Entry ID does not exist or has been deleted."""


class DuplicateEntryError(PyBinDBError):
    """Raised when attempting to create a Data Entry with an ID that already exists."""


class SerializationError(PyBinDBError):
    """Raised when serializing or deserializing a BinarySerializable object fails."""

