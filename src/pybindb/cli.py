"""Typer CLI for pybindb database management, user/group creation, and entry CRUD."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from yubikit.piv import SLOT

from pybindb.constants import (
    DEFAULT_BLOCK_SIZE,
    WIN_VAULT_SERVICE_NAME,
    DataType,
)
from pybindb.crypto.win_vault import InMemoryVaultProvider, WindowsVaultManager
from pybindb.crypto.yubikey import (
    HardwareKeyProvider,
    PivYubiKeyProvider,
    SimulatedYubiKeyProvider,
)
from pybindb.database import BinaryDatabase
from pybindb.models.entities import GroupEntry, decode_fixed_string

app = typer.Typer(
    name="pybindb",
    help="Encrypted Binary Block Database CLI with Windows Vault and YubiKey PIV support.",
    no_args_is_help=True,
)


def _resolve_vault(
    service_name: str,
    hex_master_key: str | None,
) -> WindowsVaultManager:
    if hex_master_key:
        key_bytes = bytes.fromhex(hex_master_key)
        return WindowsVaultManager(
            provider=InMemoryVaultProvider(initial_key=key_bytes),
            service_name=service_name,
        )
    return WindowsVaultManager(service_name=service_name)


def _resolve_yubikey(
    sim_store: Path | None,
    pin: str,
    slot: int,
) -> HardwareKeyProvider:
    if sim_store is not None:
        return SimulatedYubiKeyProvider(storage_path=sim_store)
    return PivYubiKeyProvider(pin=pin, default_slot=SLOT(slot))


@app.command("init")
def init_db(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    block_size: Annotated[
        int, typer.Option("--block-size", "-b", help="Physical block size in bytes (>=512).")
    ] = DEFAULT_BLOCK_SIZE,
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Initialize a new encrypted binary database file."""
    vault = _resolve_vault(vault_service, master_key_hex)
    with BinaryDatabase.create(
        path=db_path,
        block_size=block_size,
        vault_manager=vault,
    ) as db:
        typer.echo(
            f"Initialized database at {db_path} "
            f"(block_size={db.header.block_size}, usable_block_size={db.header.usable_block_size})."
        )


@app.command("info")
def info_db(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Display header metadata, block utilization, entities, and data entries."""
    vault = _resolve_vault(vault_service, master_key_hex)
    with BinaryDatabase.open(path=db_path, vault_manager=vault) as db:
        h = db.header
        typer.echo(f"Database: {db_path}")
        typer.echo(f"  Format Version : {h.version}")
        typer.echo(f"  Block Size     : {h.block_size} bytes (usable {h.usable_block_size} bytes)")
        typer.echo(f"  Blocks Total   : {h.blocks_total}")
        typer.echo(f"  Free Block Head: 0x{h.free_block_head:08X}")
        typer.echo(
            f"  Entities       : {len(db.cache.entities)} "
            f"({len(db.cache.entities.all_users())} users, {len(db.cache.entities.all_groups())} groups)"
        )
        for ent in db.cache.entities.all_entities():
            eid_str = decode_fixed_string(ent.entity_id) or ent.entity_id.hex()
            if isinstance(ent, GroupEntry):
                typer.echo(f"    - [GROUP] id={eid_str!r} name={ent.name!r} members={ent.member_count}")
            else:
                typer.echo(f"    - [USER]  id={eid_str!r} name={ent.name!r}")

        typer.echo(f"  Data Entries   : {len(db.cache.data_entries)} active")
        for d in db.cache.data_entries.all_entries():
            did_str = decode_fixed_string(d.entry_id) or d.entry_id.hex()
            owner_str = decode_fixed_string(d.entity_id) or d.entity_id.hex()
            typer.echo(
                f"    - [ENTRY] id={did_str!r} name={d.name!r} owner={owner_str!r} "
                f"type={d.data_type.name} tag={d.type_tag!r} blocks={d.block_count} bytes={d.payload_length}"
            )


@app.command("user-create")
def user_create(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    entity_id: Annotated[str, typer.Option("--id", help="Unique user entity ID.")],
    name: Annotated[str, typer.Option("--name", help="User display name.")],
    slot: Annotated[int, typer.Option("--slot", help="YubiKey PIV slot (default 0x9d = 157).")] = 0x9D,
    pin: Annotated[str, typer.Option("--pin", help="YubiKey PIV PIN.")] = "123456",
    sim_store: Annotated[
        Optional[Path], typer.Option("--sim-store", help="Path to SimulatedYubiKey JSON store.")
    ] = None,
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Create a new User entity in the database."""
    vault = _resolve_vault(vault_service, master_key_hex)
    yk = _resolve_yubikey(sim_store, pin, slot)
    with BinaryDatabase.open(
        path=db_path,
        vault_manager=vault,
        yubikey_provider=yk,
    ) as db:
        user = db.create_user(entity_id=entity_id, name=name, yubikey_slot=slot)
        typer.echo(f"Created User {user.name!r} (id={entity_id!r}).")


@app.command("group-create")
def group_create(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    entity_id: Annotated[str, typer.Option("--id", help="Unique group entity ID.")],
    name: Annotated[str, typer.Option("--name", help="Group display name.")],
    member: Annotated[
        list[str], typer.Option("--member", "-m", help="Member entity ID (repeatable).")
    ],
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Create a new Group entity and wrap the group private key for all specified members."""
    vault = _resolve_vault(vault_service, master_key_hex)
    with BinaryDatabase.open(path=db_path, vault_manager=vault) as db:
        grp = db.create_group(entity_id=entity_id, name=name, member_ids=member)
        typer.echo(
            f"Created Group {grp.name!r} (id={entity_id!r}) with {grp.member_count} members."
        )


@app.command("write")
def write_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    entry_id: Annotated[str, typer.Option("--id", help="Unique data entry ID.")],
    name: Annotated[str, typer.Option("--name", help="Entry display name.")],
    target: Annotated[str, typer.Option("--target", help="Target User or Group entity ID.")],
    text: Annotated[Optional[str], typer.Option("--text", help="UTF-8 text content to store.")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", help="Path to binary file to store.")] = None,
    data_type: Annotated[
        Optional[str], typer.Option("--type", help="DataType: RAW, TEXT, IMAGE, AUDIO.")
    ] = None,
    type_tag: Annotated[str, typer.Option("--tag", help="16-char subtype or MIME tag.")] = "",
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Encrypt and write a Data Entry into the database."""
    if (text is None) == (file is None):
        raise typer.BadParameter("Provide exactly one of --text or --file.")

    dtype: DataType | None = None
    if data_type is not None:
        dtype = DataType[data_type.upper()]

    payload: bytes | str = text if text is not None else file.read_bytes()  # type: ignore[union-attr]
    vault = _resolve_vault(vault_service, master_key_hex)
    with BinaryDatabase.open(path=db_path, vault_manager=vault) as db:
        entry = db.write_entry(
            entry_id=entry_id,
            name=name,
            data=payload,
            target_entity_id=target,
            data_type=dtype,
            type_tag=type_tag,
        )
        typer.echo(
            f"Wrote entry {entry.name!r} (id={entry_id!r}, blocks={entry.block_count}, "
            f"payload_length={entry.payload_length})."
        )


@app.command("read")
def read_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    entry_id: Annotated[str, typer.Option("--id", help="Data entry ID to read.")],
    reader: Annotated[str, typer.Option("--reader", help="Reader User entity ID.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write raw bytes to file.")] = None,
    slot: Annotated[int, typer.Option("--slot", help="YubiKey PIV slot.")] = 0x9D,
    pin: Annotated[str, typer.Option("--pin", help="YubiKey PIV PIN.")] = "123456",
    sim_store: Annotated[
        Optional[Path], typer.Option("--sim-store", help="Path to SimulatedYubiKey JSON store.")
    ] = None,
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Read and decrypt a Data Entry using a User's hardware or simulated YubiKey."""
    vault = _resolve_vault(vault_service, master_key_hex)
    yk = _resolve_yubikey(sim_store, pin, slot)
    with BinaryDatabase.open(
        path=db_path,
        vault_manager=vault,
        yubikey_provider=yk,
    ) as db:
        if output is not None:
            raw_bytes = db.read_entry(
                entry_id=entry_id,
                reader_entity_id=reader,
                yubikey_slot=slot,
                deserialize=False,
            )
            output.write_bytes(raw_bytes)
            typer.echo(f"Wrote {len(raw_bytes)} decrypted bytes to {output}.")
        else:
            result = db.read_entry(
                entry_id=entry_id,
                reader_entity_id=reader,
                yubikey_slot=slot,
                deserialize=True,
            )
            if isinstance(result, bytes):
                typer.echo(result.hex())
            else:
                typer.echo(str(result))


@app.command("delete")
def delete_cmd(
    db_path: Annotated[Path, typer.Argument(help="Path to the .bdb database file.")],
    entry_id: Annotated[str, typer.Option("--id", help="Data entry ID to delete.")],
    vault_service: Annotated[
        str, typer.Option("--vault-service", help="Windows Credential Manager service name.")
    ] = WIN_VAULT_SERVICE_NAME,
    master_key_hex: Annotated[
        Optional[str], typer.Option("--master-key-hex", help="Optional 64-char hex master key.")
    ] = None,
) -> None:
    """Delete a Data Entry and reclaim its blocks onto the free list."""
    vault = _resolve_vault(vault_service, master_key_hex)
    with BinaryDatabase.open(path=db_path, vault_manager=vault) as db:
        db.delete_entry(entry_id)
        typer.echo(f"Deleted entry {entry_id!r}.")


if __name__ == "__main__":
    app()

