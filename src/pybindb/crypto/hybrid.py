"""Hybrid cryptography primitives for block-level and entry-level encryption."""

from __future__ import annotations

import os
import struct
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pybindb.constants import (
    AES_KEY_SIZE,
    BLOCK_NONCE_SIZE,
    BLOCK_OVERHEAD,
    BLOCK_TAG_SIZE,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_WRAPPED_KEY_LENGTH,
    ENTRY_STREAM_HEADER_SIZE,
    MIN_BLOCK_SIZE,
    RSA_KEY_BITS,
    RSA_OAEP_CIPHERTEXT_LENGTH,
    RSA_PUBLIC_KEY_DER_LENGTH,
)
from pybindb.exceptions import (
    BlockAuthenticationError,
    CryptoError,
    EntryAuthenticationError,
)


def _oaep_padding() -> padding.OAEP:
    """Return standard RSA-OAEP-SHA256 padding instance."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA-2048 keypair and return (public_key_der, private_key_der).

    public_key_der is encoded as DER SubjectPublicKeyInfo (294 bytes).
    private_key_der is encoded as DER PKCS#8 without encryption.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if len(public_key_der) != RSA_PUBLIC_KEY_DER_LENGTH:
        raise CryptoError(
            f"Unexpected RSA-2048 DER public key length: {len(public_key_der)}"
        )
    return public_key_der, private_key_der


def rsa_oaep_encrypt(public_key_der: bytes, plaintext: bytes) -> bytes:
    """Encrypt a small payload (e.g., 32-byte AES key) using RSA-2048-OAEP-SHA256."""
    try:
        pub_key = serialization.load_der_public_key(public_key_der)
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise CryptoError("Loaded public key is not an RSA public key.")
        return pub_key.encrypt(plaintext, _oaep_padding())
    except Exception as exc:
        if isinstance(exc, CryptoError):
            raise
        raise CryptoError(f"RSA-OAEP encryption failed: {exc}") from exc


def rsa_oaep_decrypt(private_key_der: bytes, ciphertext: bytes) -> bytes:
    """Decrypt an RSA-2048-OAEP-SHA256 ciphertext using a DER PKCS#8 private key."""
    try:
        priv_key = serialization.load_der_private_key(private_key_der, password=None)
        if not isinstance(priv_key, rsa.RSAPrivateKey):
            raise CryptoError("Loaded private key is not an RSA private key.")
        return priv_key.decrypt(ciphertext, _oaep_padding())
    except Exception as exc:
        if isinstance(exc, CryptoError):
            raise
        raise EntryAuthenticationError(f"RSA-OAEP decryption failed: {exc}") from exc


def encrypt_block(
    manager_key: bytes,
    block_index: int,
    usable_data: bytes | memoryview,
    next_block_ptr: int,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bytes:
    """Encrypt a single physical block (i >= 1) using the Windows Manager key.

    Physical Disk Layout (B bytes total):
      - nonce: 12 bytes
      - ciphertext: B - 28 bytes (usable_data [B - 32 bytes] + next_block_ptr [<I, 4 bytes])
      - auth_tag: 16 bytes (AAD = struct.pack('<I', block_index))
    """
    if len(manager_key) != AES_KEY_SIZE:
        raise CryptoError(f"Manager key must be {AES_KEY_SIZE} bytes, got {len(manager_key)}.")
    if block_size < MIN_BLOCK_SIZE:
        raise ValueError(f"block_size must be >= {MIN_BLOCK_SIZE}, got {block_size}.")

    usable_capacity = block_size - BLOCK_OVERHEAD
    raw_usable = bytes(usable_data)
    if len(raw_usable) > usable_capacity:
        raise ValueError(
            f"usable_data length ({len(raw_usable)}) exceeds block usable capacity ({usable_capacity})."
        )
    if len(raw_usable) < usable_capacity:
        raw_usable = raw_usable + b"\x00" * (usable_capacity - len(raw_usable))

    plaintext = raw_usable + struct.pack("<I", next_block_ptr & 0xFFFFFFFF)
    nonce = os.urandom(BLOCK_NONCE_SIZE)
    aad = struct.pack("<I", block_index)
    aesgcm = AESGCM(manager_key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct_and_tag


def decrypt_block(
    manager_key: bytes,
    block_index: int,
    raw_block: bytes | memoryview,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> tuple[bytes, int]:
    """Decrypt a single physical block (i >= 1) using the Windows Manager key.

    Returns (usable_data, next_block_ptr).
    Raises BlockAuthenticationError if AAD or ciphertext integrity check fails.
    """
    if len(manager_key) != AES_KEY_SIZE:
        raise CryptoError(f"Manager key must be {AES_KEY_SIZE} bytes, got {len(manager_key)}.")
    if len(raw_block) != block_size:
        raise BlockAuthenticationError(
            f"Expected raw_block of {block_size} bytes, got {len(raw_block)}."
        )

    raw_bytes = bytes(raw_block)
    nonce = raw_bytes[:BLOCK_NONCE_SIZE]
    ct_and_tag = raw_bytes[BLOCK_NONCE_SIZE:]
    aad = struct.pack("<I", block_index)
    aesgcm = AESGCM(manager_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, aad)
    except InvalidTag as exc:
        raise BlockAuthenticationError(
            f"Block {block_index} authentication failed (tampered data, wrong key, or swapped block)."
        ) from exc

    usable_data = plaintext[:-4]
    (next_block_ptr,) = struct.unpack("<I", plaintext[-4:])
    return usable_data, next_block_ptr


def wrap_group_private_key(
    member_public_key_der: bytes,
    group_private_key_der: bytes,
    wrapped_key_length: int = DEFAULT_WRAPPED_KEY_LENGTH,
) -> bytes:
    """Hybrid-encrypt a Group PKCS#8 DER private key for a specific member's RSA public key.

    Layout (exact constant length W_len = wrapped_key_length):
      - wrapped_k_wrap: 256 bytes (RSA-OAEP-SHA256 encrypted 32-byte AES key)
      - nonce: 12 bytes
      - ciphertext + tag: (W_len - 268) bytes (AES-256-GCM over length-prefixed padded DER private key)
    """
    padded_plaintext_len = (
        wrapped_key_length - RSA_OAEP_CIPHERTEXT_LENGTH - BLOCK_NONCE_SIZE - BLOCK_TAG_SIZE
    )
    if padded_plaintext_len < len(group_private_key_der) + 2:
        raise CryptoError(
            f"wrapped_key_length ({wrapped_key_length}) is too small for group private key "
            f"({len(group_private_key_der)} bytes)."
        )

    k_wrap = os.urandom(AES_KEY_SIZE)
    wrapped_k_wrap = rsa_oaep_encrypt(member_public_key_der, k_wrap)

    framed_privkey = (
        struct.pack("<H", len(group_private_key_der))
        + group_private_key_der
        + b"\x00" * (padded_plaintext_len - 2 - len(group_private_key_der))
    )
    nonce = os.urandom(BLOCK_NONCE_SIZE)
    ct_and_tag = AESGCM(k_wrap).encrypt(nonce, framed_privkey, None)
    blob = wrapped_k_wrap + nonce + ct_and_tag
    assert len(blob) == wrapped_key_length
    return blob


def unwrap_group_private_key(
    member_decryptor: Callable[[bytes], bytes] | rsa.RSAPrivateKey,
    wrapped_blob: bytes | memoryview,
    wrapped_key_length: int = DEFAULT_WRAPPED_KEY_LENGTH,
) -> bytes:
    """Unwrap a Group PKCS#8 DER private key using a member's private key decryptor."""
    raw = bytes(wrapped_blob)
    if len(raw) != wrapped_key_length:
        raise EntryAuthenticationError(
            f"Expected wrapped group key of {wrapped_key_length} bytes, got {len(raw)}."
        )

    wrapped_k_wrap = raw[:RSA_OAEP_CIPHERTEXT_LENGTH]
    nonce = raw[RSA_OAEP_CIPHERTEXT_LENGTH : RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE]
    ct_and_tag = raw[RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE :]

    try:
        if isinstance(member_decryptor, rsa.RSAPrivateKey):
            k_wrap = member_decryptor.decrypt(wrapped_k_wrap, _oaep_padding())
        else:
            k_wrap = member_decryptor(wrapped_k_wrap)
        framed_privkey = AESGCM(k_wrap).decrypt(nonce, ct_and_tag, None)
    except Exception as exc:
        if isinstance(exc, EntryAuthenticationError):
            raise
        raise EntryAuthenticationError(f"Failed to unwrap group private key: {exc}") from exc

    (der_len,) = struct.unpack("<H", framed_privkey[:2])
    if der_len <= 0 or 2 + der_len > len(framed_privkey):
        raise EntryAuthenticationError("Corrupted length prefix in unwrapped group private key.")
    return framed_privkey[2 : 2 + der_len]


def encrypt_entry_stream(
    public_key_der: bytes,
    entry_id: bytes,
    plaintext: bytes | memoryview,
) -> bytes:
    """Encrypt a whole data entry payload for an entity's RSA-2048 public key.

    Encrypted Entry Stream format (Section 5.2):
      Wrapped DEK (256B) || Nonce (12B) || Tag (16B) || Ciphertext (N B)
    """
    dek = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(BLOCK_NONCE_SIZE)
    aesgcm = AESGCM(dek)
    ct_and_tag = aesgcm.encrypt(nonce, bytes(plaintext), bytes(entry_id))
    ciphertext = ct_and_tag[:-BLOCK_TAG_SIZE]
    tag = ct_and_tag[-BLOCK_TAG_SIZE:]

    wrapped_dek = rsa_oaep_encrypt(public_key_der, dek)
    return wrapped_dek + nonce + tag + ciphertext


def decrypt_entry_stream(
    private_key_decryptor: Callable[[bytes], bytes] | rsa.RSAPrivateKey,
    entry_id: bytes,
    encrypted_stream: bytes | memoryview,
) -> bytes:
    """Decrypt an Encrypted Entry Stream using a hardware/software RSA-OAEP decryptor.

    Expects:
      Wrapped DEK (256B) || Nonce (12B) || Tag (16B) || Ciphertext (N B)
    with entry_id bound as AES-GCM AAD.
    """
    raw = bytes(encrypted_stream)
    if len(raw) < ENTRY_STREAM_HEADER_SIZE:
        raise EntryAuthenticationError(
            f"Encrypted entry stream is too short ({len(raw)} bytes < {ENTRY_STREAM_HEADER_SIZE} bytes)."
        )

    wrapped_dek = raw[:RSA_OAEP_CIPHERTEXT_LENGTH]
    nonce = raw[RSA_OAEP_CIPHERTEXT_LENGTH : RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE]
    tag = raw[
        RSA_OAEP_CIPHERTEXT_LENGTH + BLOCK_NONCE_SIZE : ENTRY_STREAM_HEADER_SIZE
    ]
    ciphertext = raw[ENTRY_STREAM_HEADER_SIZE:]

    try:
        if isinstance(member := private_key_decryptor, rsa.RSAPrivateKey):
            dek = member.decrypt(wrapped_dek, _oaep_padding())
        else:
            dek = private_key_decryptor(wrapped_dek)
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ciphertext + tag, bytes(entry_id))
    except Exception as exc:
        if isinstance(exc, EntryAuthenticationError):
            raise
        raise EntryAuthenticationError(
            f"Entry stream authentication or decryption failed: {exc}"
        ) from exc

