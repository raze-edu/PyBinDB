# pybindb — Encrypted Binary Block Database

`pybindb` is a Python library and CLI tool that manages a custom, random-access encrypted binary database stored inside a single file. It supports storing arbitrary data entries—including text, images, audio, raw binaries, and custom strongly-typed Python objects (with primitive, hex/bytes, and fixed-size array attributes)—across chained fixed-size blocks.

## Features
- **Two-Layer Encryption Hierarchy:**
  - **Outer Layer (Windows Manager Block-Level Encryption):** Every individual block (and the encrypted portion of Block 0) is encrypted with AES-256-GCM using a 256-bit master key managed via Windows Credential Manager (`WinVaultKeyring`), binding the physical block index as AAD.
  - **Inner Layer (User / Group Entry-Level Encryption):** Every Data Entry payload is encrypted as a single contiguous stream using an ephemeral AES-256-GCM DEK (with `entry_id` as AAD) and RSA-2048-OAEP-SHA256 key wrapping for the target User or Group.
- **Hardware & Simulated YubiKey PIV Support:** Supports RSA-2048 key generation and hardware OAEP decryption via YubiKey PIV slots (`PivYubiKeyProvider`) as well as an in-memory/file simulator (`SimulatedYubiKeyProvider`).
- **Automatic & Explicit Group Key Distribution:** Hybrid RSA-OAEP + AES-256-GCM wrapping of Group private keys for multi-member access without duplicating entry ciphertexts.
- **Chained Block Storage & $O(1)$ Free-List Reclamation:** Fixed-size blocks with `uint32` next-block pointers (`EOF_BLOCK = 0xFFFFFFFF`), partial table block updates, LRU block cache, and $O(1)$startup index caching.
- **Declarative Binary Object Serialization (`BinarySerializable`):** Supports `PrimitiveField`, `StringField`, `HexBytesField`, and 1D/ND `ArrayField` with single-pass `struct` compilation.

