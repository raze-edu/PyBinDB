# Coding Agent Specification: Encrypted Binary Block Database (`pybindb`)

## 1. System Overview & Core Architecture
`pybindb` is a Python library and CLI tool that manages a custom, random-access encrypted binary database stored inside a single file. It supports storing arbitrary data entries—including text, images, audio, raw binaries, and custom strongly-typed Python objects (with primitive, hex/bytes, and fixed-size array attributes)—across chained fixed-size blocks.

### Core Architectural Decisions
1. **Two-Layer Encryption Hierarchy:**
   - **Inner Layer (User / Group Entry-Level Encryption):** Every Data Entry payload is encrypted *as a single contiguous unit* using hybrid encryption associated with a specific User or Group Entity before being split into blocks.
   - **Outer Layer (Windows Manager Block-Level Encryption):** Every individual block written to the binary file (except the plaintext magic/size bootstrap prefix in Block 0) is encrypted independently using the Windows Manager master key retrieved from the Windows Credential Manager (Windows Vault).
2. **Chained Block Storage with Free-List Tracking:**
   - Every block reserves a 32-bit address pointer (`uint32`) at the end of its decrypted payload pointing to the next block index in the chain, or `0xFFFFFFFF` (`EOF_BLOCK`) to mark the end of the chain.
   - Freed blocks from deleted or shrunk entries are chained together via a `free_block_head` pointer in the Database Header for $O(1)$ block reclamation.
3. **In-Memory Startup Caching for Variable-Length Entities:**
   - Because Group Entries contain a variable number of member pairs `(entity_id, encrypted_private_key)`, the engine scans the Entity Table stream once on database initialization and caches `(entity_id -> stream_offset, byte_length, parsed_entity)` in memory for $O(1)$ lookup and targeted updates.
4. **Exact Payload Framing:**
   - Each Data Entry stores both `block_count` (number of blocks allocated) and `payload_length` (exact byte length of the encrypted entry payload) so trailing padding bytes inside the final block of a chain are stripped deterministically.

---

## 2. Technology Stack & Dependencies
- **Python Version:** Python $\ge 3.11$
- **Core Dependencies:**
  - `cryptography >= 42.0.0` (AES-256-GCM block/stream encryption, RSA-2048 / OAEP asymmetric key wrapping)
  - `keyring >= 25.0.0` + `pywin32-ctypes` (Windows Credential Manager integration via `WinVaultKeyring`)
  - `yubikey-manager >= 5.4.0` (`ykman` / `yubikit.piv` for YubiKey PIV key generation and hardware decryption)
  - `typer >= 0.12.0` (CLI interface for database management and inspection)
- **Dev / Test Dependencies:**
  - `pytest >= 8.0.0`
  - `pytest-cov`

---

## 3. Binary Layout & Data Structures
All multi-byte integer fields use **Little-Endian (`<`)** byte ordering.

### 3.1 Constants & Special Pointers
- `MAGIC_HEX_TAG = b"BDB1"` (`0x31424442` in little-endian)
- `FORMAT_VERSION = 1` (`uint16`)
- `EOF_BLOCK = 0xFFFFFFFF` ($2^{32} - 1$)
- `USER_FLAG_SET = 0x01` (Indicates a User Entry; entry ends after the flag)
- `USER_FLAG_GROUP = 0x00` (Indicates a Group Entry; followed by member count and member array)

### 3.2 Block Structure & Manager Block-Level Encryption
Let the configured physical block size be $B$ bytes (e.g., $B = 4096\text{ bytes}$, minimum $B \ge 512\text{ bytes}$).

For every encrypted block $i \in \{1, \dots, N-1\}$:
- **Physical Disk Layout ($B\text{ bytes}$ total):**
  - `nonce`: $12\text{ bytes}$ (96-bit random nonce for AES-256-GCM)
  - `ciphertext`: $B - 28\text{ bytes}$ (Encrypted block payload)
  - `auth_tag`: $16\text{ bytes}$ (128-bit GCM authentication tag, using block index $i$ encoded as `<I` as Associated Authenticated Data / AAD to prevent block-swapping attacks)
- **Decrypted Block Layout ($B - 28\text{ bytes}$ total):**
  - `usable_data`: $U = B - 32\text{ bytes}$ of raw stream data
  - `next_block_ptr`: $4\text{ bytes}$ (`<I`, `uint32` index of the next block in the chain, or `0xFFFFFFFF` for `EOF_BLOCK`)

$$U = B - 12_{\text{nonce}} - 16_{\text{tag}} - 4_{\text{ptr}} = B - 32\text{ bytes}$$

### 3.3 Block 0: Database Header
Block 0 contains an unencrypted 12-byte bootstrap prefix (so the engine knows the block size $B$ before decrypting) followed by the Manager-encrypted Header Payload.

#### Unencrypted Bootstrap Prefix ($12\text{ bytes}$)
| Field | Type | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| `magic` | `4s` | 4 | Fixed hex tag `b"BDB1"` (`0x42 0x44 0x42 0x31`) |
| `version` | `<H` (`uint16`) | 2 | Format version (`1`) |
| `reserved` | `<H` (`uint16`) | 2 | Reserved flags (`0`) |
| `block_size` | `<I` (`uint32`) | 4 | Block size $B$ in bytes |

#### Encrypted Header Payload (Inside Block 0 Ciphertext)
| Field | Type | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| `blocks_total` | `<I` (`uint32`) | 4 | Total number of blocks currently in the file |
| `free_block_head` | `<I` (`uint32`) | 4 | First block index in the free-block chain (`0xFFFFFFFF` if none) |
| `key_length` | `<I` (`uint32`) | 4 | Fixed byte size $K_{\text{len}}$ of serialized public/encrypted keys (e.g., `294` for DER RSA-2048 public key, `256` for RSA ciphertext) |
| `wrapped_key_length` | `<I` (`uint32`) | 4 | Fixed byte size $W_{\text{len}}$ of an entity-encrypted private key blob |
| `entity_id_length` | `<H` (`uint16`) | 2 | Configurable byte length $L_{\text{eid}}$ of `entity_id` |
| `entity_name_length` | `<H` (`uint16`) | 2 | Configurable byte length $L_{\text{ename}}$ of `entity_name` |
| `entry_id_length` | `<H` (`uint16`) | 2 | Configurable byte length $L_{\text{did}}$ of `entry_id` |
| `entry_name_length` | `<H` (`uint16`) | 2 | Configurable byte length $L_{\text{dname}}$ of `entry_name` |
| `entity_table_start` | `<I` (`uint32`) | 4 | Entity Table `start_block` index |
| `entity_table_last` | `<I` (`uint32`) | 4 | Entity Table `last_block` index |
| `entity_table_count` | `<I` (`uint32`) | 4 | Entity Table `number_of_entries` |
| `entity_table_bytes` | `<Q` (`uint64`) | 8 | Active byte length of the Entity Table stream |
| `data_table_start` | `<I` (`uint32`) | 4 | Data Entry Table `start_block` index |
| `data_table_last` | `<I` (`uint32`) | 4 | Data Entry Table `last_block` index |
| `data_table_count` | `<I` (`uint32`) | 4 | Data Entry Table `number_of_entries` |

---

## 4. Entity Table & User / Group Records
The Entity Table is stored as a contiguous logical byte stream spanning the block chain starting at `entity_table_start` and ending at `entity_table_last`.

### 4.1 User Entry Layout
Fixed size: $S_{\text{user}} = L_{\text{eid}} + L_{\text{ename}} + K_{\text{len}} + 1\text{ bytes}$.
| Field | Size (Bytes) | Description |
| :--- | :--- | :--- |
| `entity_id` | $L_{\text{eid}}$ | Unique identifier (zero-padded bytes/UTF-8 or raw UUID bytes) |
| `name` | $L_{\text{ename}}$ | Null-padded UTF-8 name of the user |
| `public_key` | $K_{\text{len}}$ | DER-encoded SubjectPublicKeyInfo (RSA-2048) |
| `user_flag` | $1$ (`uint8`) | `0x01` (Set flag: marks record as a User Entry and terminates record) |

### 4.2 Group Entry Layout
Created automatically or explicitly for any unique set of member entities.
Variable size: $S_{\text{group}}(M) = L_{\text{eid}} + L_{\text{ename}} + K_{\text{len}} + 1 + 4 + M \times (L_{\text{eid}} + W_{\text{len}})\text{ bytes}$.
| Field | Size (Bytes) | Description |
| :--- | :--- | :--- |
| `entity_id` | $L_{\text{eid}}$ | Unique identifier for the Group |
| `name` | $L_{\text{ename}}$ | Null-padded UTF-8 group name |
| `public_key` | $K_{\text{len}}$ | DER-encoded RSA-2048 public key of the group |
| `user_flag` | $1$ (`uint8`) | `0x00` (Unset flag: indicates Group Entry; parser continues reading) |
| `member_count` | $4$ (`<I`, `uint32`) | Number of members $M$ in the group |
| `members` | $M \times (L_{\text{eid}} + W_{\text{len}})$ | Repeated $M$ times: `member_entity_id` ($L_{\text{eid}}$) + `encrypted_group_privkey` ($W_{\text{len}}$) |

> **Group Private Key Wrapping:** Because an RSA-2048 private key in DER format exceeds the maximum direct payload size of RSA-2048-OAEP, `encrypted_group_privkey` ($W_{\text{len}}$ bytes) is produced via hybrid key wrapping:
> 1. Generate a random 32-byte AES-256 key $K_{\text{wrap}}$.
> 2. Encrypt $K_{\text{wrap}}$ with the member's public key using RSA-OAEP-SHA256 ($256\text{ bytes}$).
> 3. Encrypt the fixed-size padded PKCS#8 Group Private Key with $K_{\text{wrap}}$ using AES-256-GCM ($12\text{B nonce} + \text{ciphertext} + 16\text{B tag}$).
> 4. Store the concatenated blob of exact constant length $W_{\text{len}}$.

---

## 5. Data Entry Table & Data Entries
The Data Entry Table is a contiguous logical byte stream spanning the block chain from `data_table_start` to `data_table_last`. Every record in the Data Entry Table has a **fixed size**, enabling both $O(1)$ offset indexing and startup caching.

### 5.1 Data Entry Record Layout
Fixed size: $S_{\text{data}} = L_{\text{did}} + L_{\text{eid}} + L_{\text{dname}} + 1 + 16 + 4 + 4 + 8\text{ bytes}$.
| Field | Type / Size | Description |
| :--- | :--- | :--- |
| `entry_id` | $L_{\text{did}}$ bytes | Unique ID of the data entry (`0x00...00` tombstone if deleted) |
| `entity_id` | $L_{\text{eid}}$ bytes | ID of the User or Group whose public key encrypted this entry |
| `name` | $L_{\text{dname}}$ bytes | Null-padded UTF-8 entry name |
| `data_type` | `<B` (`uint8`, 1B) | Enum: `1=RAW`, `2=TEXT`, `3=IMAGE`, `4=AUDIO`, `5=PYTHON_OBJECT` |
| `type_tag` | `16s` (16B) | Null-padded ASCII/hex tag identifying MIME subtype or registered Python class name |
| `address` | `<I` (`uint32`, 4B) | Start block index of the entry's payload chain |
| `block_count` | `<I` (`uint32`, 4B) | Total number of blocks allocated to this entry |
| `payload_length` | `<Q` (`uint64`, 8B) | Exact byte length of the encrypted entry payload stream |

### 5.2 Whole-Entry Encryption Format (User / Group Layer)
When a Data Entry is written for `entity_id`:
1. Serialize the raw data (file bytes, UTF-8 bytes, or `BinarySerializable.to_bytes()`).
2. Generate an ephemeral 256-bit Data Encryption Key (`DEK`) and 12-byte `nonce`.
3. Encrypt the serialized bytes as a single contiguous payload using AES-256-GCM with `DEK` and `entry_id` as AAD.
4. Wrap `DEK` using the target User or Group `public_key` via RSA-OAEP-SHA256 ($256\text{ bytes}$).
5. Form the **Encrypted Entry Stream**:
   $$\text{Stream} = \underbrace{\text{Wrapped DEK}}_{256\text{ B}} \parallel \underbrace{\text{Nonce}}_{12\text{ B}} \parallel \underbrace{\text{Tag}}_{16\text{ B}} \parallel \underbrace{\text{Ciphertext}}_{N\text{ B}}$$
6. Record `payload_length = len(Stream)` in the Data Entry Table and slice `Stream` into $\lceil \text{len(Stream)} / U \rceil$ blocks, encrypting each block individually with the Windows Manager key.

---

## 6. Custom Python Object & Fixed-Array Serialization (`BinarySerializable`)
To store custom Python objects with strictly typed, fixed-size attributes (including fixed-length arrays and hex/byte tags), implement a declarative schema system in `src/pybindb/serialization.py`.

### 6.1 Supported Field Descriptors
1. **`PrimitiveField(fmt: str)`**: Wraps standard `struct` formats (`i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `f32`, `f64`, `bool`).
2. **`StringField(length: int, encoding: str = "utf-8")`**: Fixed-length null-padded string.
3. **`HexBytesField(length: int)`**: Fixed-length raw bytes or hex-encoded tag (`bytes` or hex `str` converted to exact `length` bytes).
4. **`ArrayField(element_field: FieldDescriptor, shape: int | tuple[int, ...])`**:
   - Supports 1D and multi-dimensional fixed-size arrays of any `PrimitiveField`, `StringField`, `HexBytesField`, or nested `BinarySerializable` object.
   - Total byte size is $\prod \text{shape} \times \text{element\_field.byte\_size}$.
   - For numeric 1D/ND arrays, compiles directly into a single contiguous `struct` format string (e.g., `<64f` for a $8 \times 8$ `f32` matrix) for fast packing/unpacking.

### 6.2 `BinarySerializable` Base Class Contract
```python
class BinarySerializable:
    TYPE_TAG: ClassVar[str]  # Max 16 ASCII chars, registered in global TypeRegistry
    
    @classmethod
    def byte_size(cls) -> int: ...
    
    def to_bytes(self) -> bytes: ...
    
    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> Self: ...
```

---

## 7. Hardware & OS Key Management

### 7.1 Windows Manager Key (`WindowsVaultManager`)
- Uses `keyring` with the `keyring.backends.Windows.WinVaultKeyring` backend (falling back to an injectable `KeyProvider` interface for unit tests).
- Service Name: `"pybindb_manager"`, Username: current Windows user (`getpass.getuser()`).
- Stores a 32-byte (256-bit) master key encoded as base64.
- Provides `encrypt_block(block_idx: int, plaintext: bytes) -> bytes` and `decrypt_block(block_idx: int, ciphertext: bytes) -> bytes`.

### 7.2 YubiKey Hardware Provider (`YubiKeyProvider`)
- Abstracts YubiKey operations behind a `HardwareKeyProvider` protocol with two implementations:
  1. `PivYubiKeyProvider`: Uses `yubikey-manager` (`yubikit.piv.PivSession`) to generate an RSA-2048 keypair on the YubiKey PIV slot (default `SLOT.KEY_MANAGEMENT` / `0x9d` or configurable slot `0x82`–`0x95`) during User creation, and performs hardware RSA-OAEP decryption when reading User-encrypted entries or unwrapping a Group private key.
  2. `SimulatedYubiKeyProvider`: In-memory/encrypted-file hardware token simulator for automated `pytest` verification and machines without a physical YubiKey inserted.

---

## 8. Performance & Optimization Architecture
1. **Startup Index Caching (`TableIndexCache`):**
   - On `Database.open()`, the engine reads the Entity Table block chain once and builds an in-memory dictionary:
     `entity_cache[entity_id] = CachedEntity(stream_offset, byte_length, entity_obj)`
   - Similarly, it caches active Data Entry records:
     `data_entry_cache[entry_id] = CachedDataEntry(record_index, stream_offset, data_entry_obj)`
   - Lookups by `entity_id` or `entry_id` operate in $O(1)$ time without disk scans.
2. **Targeted Partial Block Updates:**
   - When updating an existing Data Entry's metadata or a User/Group record in-place, the engine computes the exact block index $k = \lfloor \text{stream\_offset} / U \rfloor$ in the table's block chain and re-encrypts only the affected block(s) rather than rewriting the entire table.
3. **Free-Block Linked List & Contiguous Allocation:**
   - Deleting a Data Entry links its chain of blocks onto `header.free_block_head` in $O(1)$ by updating only the last freed block's `next_block_ptr` to the old `free_block_head`.
   - Updating a Data Entry reuses its existing block chain in-place, allocating additional blocks from the free list (or EOF) if the new payload is larger, or returning excess tail blocks to the free list if smaller.
4. **Zero-Copy Slicing (`memoryview`) & LRU Block Cache:**
   - Payload splitting and reassembly must use `memoryview` and pre-allocated `bytearray(payload_length)` buffers to avoid $O(N^2)$ byte concatenation copies.
   - Maintain a configurable LRU cache for decrypted table blocks, invalidated automatically on write.

---

## 9. Target Project Structure
```text
pybindb/
├── pyproject.toml
├── README.md
├── src/
│   └── pybindb/
│       ├── __init__.py
│       ├── constants.py          # Magic bytes, enums, EOF_BLOCK
│       ├── exceptions.py         # Custom exception hierarchy
│       ├── crypto/
│       │   ├── __init__.py
│       │   ├── win_vault.py      # Windows Credential Manager integration
│       │   ├── yubikey.py        # PivYubiKeyProvider & SimulatedYubiKeyProvider
│       │   └── hybrid.py         # AES-256-GCM block/entry crypto & RSA-OAEP wrapping
│       ├── storage/
│       │   ├── __init__.py
│       │   ├── header.py         # Block 0 Header pack/unpack
│       │   ├── block_io.py       # Block reader/writer, chaining, free-list allocator
│       │   └── cache.py          # In-memory Entity & Data Entry offset caches
│       ├── models/
│       │   ├── __init__.py
│       │   ├── entities.py       # UserEntry, GroupEntry, TableDescriptor
│       │   └── entries.py        # DataEntry, DataType enum
│       ├── serialization.py      # BinarySerializable, PrimitiveField, ArrayField, HexBytesField
│       ├── database.py           # High-level BinaryDatabase manager API
│       └── cli.py                # Typer CLI for db init, user/group create, read/write
└── tests/
    ├── conftest.py
    ├── test_block_io.py          # Chaining, EOF_BLOCK, free list recycling
    ├── test_crypto.py            # Windows Vault mock, YubiKey PIV simulator, group key wrapping
    ├── test_entities.py          # Variable-length Group Entries & startup cache accuracy
    ├── test_serialization.py     # Custom Python objects, multi-dimensional ArrayField, HexBytesField
    └── test_database_e2e.py      # End-to-end CRUD for text, image, audio, and Python objects
```

---

## 10. Step-by-Step Implementation Plan for the Coding Agent

### Phase 1: Scaffolding, Constants & Cryptography Providers
1. Initialize `pyproject.toml` and package layout under `src/pybindb`.
2. Implement `win_vault.py` to get/create a 256-bit Manager key in Windows Credential Manager (`keyring`), plus an `InMemoryVaultProvider` for tests.
3. Implement `yubikey.py` with `PivYubiKeyProvider` (using `yubikit.piv`) and `SimulatedYubiKeyProvider`.
4. Implement `hybrid.py` providing:
   - `encrypt_block(manager_key, block_index, usable_data, next_block_ptr, block_size)`
   - `decrypt_block(manager_key, block_index, raw_block, block_size) -> tuple[bytes, int]`
   - `encrypt_entry_stream(public_key, entry_id, plaintext) -> bytes`
   - `decrypt_entry_stream(private_key_decryptor, entry_id, encrypted_stream) -> bytes`
5. **Verification:** Run `pytest tests/test_crypto.py` to verify block AAD binding, tamper detection, and group private key wrapping/unwrapping.

### Phase 2: Block I/O Engine, Header & Free-List Allocator
1. Implement `header.py` to serialize/deserialize Block 0 (12-byte plaintext prefix + encrypted header body).
2. Implement `block_io.py`:
   - `allocate_blocks(count: int) -> list[int]` (pulls from `free_block_head` first, then appends to EOF and increments `blocks_total`).
   - `free_block_chain(start_block: int)` (traverses chain and prepends freed blocks to `free_block_head`).
   - `write_stream_to_chain(data: bytes | memoryview, start_block: int | None) -> tuple[int, int, int]` returning `(start_block, last_block, block_count)`.
   - `read_stream_from_chain(start_block: int, exact_byte_length: int) -> bytes`.
3. **Verification:** Run `pytest tests/test_block_io.py` testing multi-block writes, exact payload truncation on the final block, and zero block leakage after repeated writes/deletes.

### Phase 3: Entity Table, Group Key Distribution & Startup Cache
1. Implement `UserEntry` and `GroupEntry` binary serialization in `models/entities.py`.
2. Implement `EntityCache` in `storage/cache.py` that parses the contiguous Entity Table byte stream on startup, distinguishing User Entries (`user_flag == 0x01`) from Group Entries (`user_flag == 0x00`) and reading the $M$ member records.
3. Implement automatic Group creation: given a unique set of `entity_id`s, compute a canonical sorted tuple, check if a Group Entry already exists for that set, and if not, generate a new Group RSA-2048 keypair, encrypt the Group private key for each member's public key, and append the `GroupEntry` to the Entity Table.
4. **Verification:** Run `pytest tests/test_entities.py` to test creating multiple users, forming groups, reloading the database from disk, and decrypting group keys via any member's YubiKey provider.

### Phase 4: Custom Python Object & Fixed-Array Serializer
1. Implement `PrimitiveField`, `StringField`, `HexBytesField`, and `ArrayField` in `serialization.py`.
2. Implement `BinarySerializable` base class with automatic `struct` compilation and type registration.
3. **Verification:** Run `pytest tests/test_serialization.py` with complex nested structs containing 1D and 2D fixed arrays, strings, and hex tags.

### Phase 5: Data Entry Table, High-Level Database API & CLI
1. Implement `DataEntry` packing/unpacking in `models/entries.py`.
2. Implement `BinaryDatabase` in `database.py` with methods:
   - `BinaryDatabase.create(path, block_size=4096, ...)`
   - `BinaryDatabase.open(path, ...)`
   - `create_user(entity_id, name, yubikey_slot=...)`
   - `create_group(entity_id, name, member_ids: list[bytes])`
   - `write_entry(entry_id, name, data, target_entity_id, data_type=...)`
   - `read_entry(entry_id, reader_entity_id)` (supports reading directly if `reader_entity_id == entry.entity_id`, or resolving via the Group Entry's member list if `entry.entity_id` is a Group!)
   - `delete_entry(entry_id)`
3. Build the `typer` CLI in `cli.py` and run full end-to-end tests (`pytest tests/test_database_e2e.py`).