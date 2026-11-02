"""YubiKey PIV hardware provider and simulated token provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)

from pybindb.crypto.hybrid import (
    generate_rsa_keypair,
    rsa_oaep_decrypt,
)
from pybindb.exceptions import AccessDeniedError, HardwareKeyError


def _normalize_slot(slot: int | SLOT) -> SLOT:
    if isinstance(slot, SLOT):
        return slot
    return SLOT(slot)


@runtime_checkable
class HardwareKeyProvider(Protocol):
    """Protocol for hardware or simulated RSA-2048 PIV key operations."""

    def generate_user_key(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Generate an RSA-2048 keypair and return the 294-byte DER SubjectPublicKeyInfo."""
        ...

    def decrypt_oaep(
        self,
        ciphertext: bytes,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Decrypt RSA-OAEP-SHA256 ciphertext using the hardware/simulated private key."""
        ...

    def get_decryptor(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> Callable[[bytes], bytes]:
        """Return a single-argument decryptor callable for hybrid unwrapping."""
        ...


class SimulatedYubiKeyProvider:
    """In-memory and optional file-persisted YubiKey PIV simulator for testing."""

    def __init__(self, storage_path: str | Path | None = None) -> None:
        self._storage_path = Path(storage_path) if storage_path is not None else None
        self._by_entity: dict[bytes, tuple[bytes, bytes]] = {}
        self._by_slot: dict[int, tuple[bytes, bytes]] = {}
        if self._storage_path is not None and self._storage_path.exists():
            self._load()

    def _save(self) -> None:
        if self._storage_path is None:
            return
        payload = {
            "by_entity": {
                eid.hex(): [pub.hex(), priv.hex()]
                for eid, (pub, priv) in self._by_entity.items()
            },
            "by_slot": {
                str(slot): [pub.hex(), priv.hex()]
                for slot, (pub, priv) in self._by_slot.items()
            },
        }
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        raw = json.loads(self._storage_path.read_text(encoding="utf-8"))
        for eid_hex, (pub_hex, priv_hex) in raw.get("by_entity", {}).items():
            self._by_entity[bytes.fromhex(eid_hex)] = (
                bytes.fromhex(pub_hex),
                bytes.fromhex(priv_hex),
            )
        for slot_str, (pub_hex, priv_hex) in raw.get("by_slot", {}).items():
            self._by_slot[int(slot_str)] = (
                bytes.fromhex(pub_hex),
                bytes.fromhex(priv_hex),
            )

    def generate_user_key(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Generate an RSA-2048 keypair in the simulator and return DER public key."""
        pub_der, priv_der = generate_rsa_keypair()
        slot_int = int(_normalize_slot(slot))
        self._by_slot[slot_int] = (pub_der, priv_der)
        if entity_id is not None:
            self._by_entity[bytes(entity_id)] = (pub_der, priv_der)
        self._save()
        return pub_der

    def register_keypair(
        self,
        public_key_der: bytes,
        private_key_der: bytes,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> None:
        """Explicitly register an existing RSA-2048 keypair in the simulator."""
        slot_int = int(_normalize_slot(slot))
        self._by_slot[slot_int] = (public_key_der, private_key_der)
        if entity_id is not None:
            self._by_entity[bytes(entity_id)] = (public_key_der, private_key_der)
        self._save()

    def get_public_key(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Retrieve the DER SubjectPublicKeyInfo for an entity or slot."""
        if entity_id is not None and bytes(entity_id) in self._by_entity:
            return self._by_entity[bytes(entity_id)][0]
        slot_int = int(_normalize_slot(slot))
        if slot_int in self._by_slot:
            return self._by_slot[slot_int][0]
        raise HardwareKeyError("No simulated key found for the given entity_id or slot.")

    def decrypt_oaep(
        self,
        ciphertext: bytes,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Decrypt RSA-OAEP-SHA256 ciphertext using the simulated private key."""
        priv_der: bytes | None = None
        if entity_id is not None and bytes(entity_id) in self._by_entity:
            priv_der = self._by_entity[bytes(entity_id)][1]
        else:
            slot_int = int(_normalize_slot(slot))
            if slot_int in self._by_slot:
                priv_der = self._by_slot[slot_int][1]
        if priv_der is None:
            raise AccessDeniedError(
                "Simulated YubiKey does not hold a private key for the requested entity or slot."
            )
        return rsa_oaep_decrypt(priv_der, ciphertext)

    def get_decryptor(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> Callable[[bytes], bytes]:
        """Return a callable `decrypt(ciphertext: bytes) -> bytes`."""
        return lambda ct: self.decrypt_oaep(ct, entity_id=entity_id, slot=slot)


class PivYubiKeyProvider:
    """Physical YubiKey PIV hardware provider using yubikey-manager (yubikit.piv)."""

    def __init__(
        self,
        pin: str | None = "123456",
        management_key: bytes = DEFAULT_MANAGEMENT_KEY,
        management_key_type: MANAGEMENT_KEY_TYPE = MANAGEMENT_KEY_TYPE.TDES,
        serial: int | None = None,
        default_slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> None:
        self.pin = pin
        self.management_key = management_key
        self.management_key_type = management_key_type
        self.serial = serial
        self.default_slot = _normalize_slot(default_slot)
        self._entity_slots: dict[bytes, SLOT] = {}

    def bind_entity_slot(self, entity_id: bytes, slot: int | SLOT) -> None:
        """Associate an entity_id with a specific PIV slot."""
        self._entity_slots[bytes(entity_id)] = _normalize_slot(slot)

    def _resolve_slot(self, entity_id: bytes | None, slot: int | SLOT | None) -> SLOT:
        if entity_id is not None and bytes(entity_id) in self._entity_slots:
            return self._entity_slots[bytes(entity_id)]
        if slot is not None:
            return _normalize_slot(slot)
        return self.default_slot

    def _open_connection(self) -> SmartCardConnection:
        try:
            from ykman.device import list_all_devices

            devices = list_all_devices([SmartCardConnection])
            for dev, info in devices:
                if self.serial is None or info.serial == self.serial:
                    return dev.open_connection(SmartCardConnection)
            raise HardwareKeyError("No matching YubiKey PIV smartcard device found.")
        except HardwareKeyError:
            raise
        except Exception as exc:
            raise HardwareKeyError(f"Failed to connect to YubiKey PIV device: {exc}") from exc

    def generate_user_key(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
    ) -> bytes:
        """Generate an RSA-2048 keypair on the physical YubiKey PIV slot and return DER public key."""
        target_slot = self._resolve_slot(entity_id, slot)
        if entity_id is not None:
            self._entity_slots[bytes(entity_id)] = target_slot
        try:
            with self._open_connection() as conn:
                session = PivSession(conn)
                session.authenticate(self.management_key_type, self.management_key)
                pub_key = session.generate_key(
                    target_slot,
                    KEY_TYPE.RSA2048,
                    pin_policy=pin_policy,
                    touch_policy=touch_policy,
                )
                if not isinstance(pub_key, rsa.RSAPublicKey):
                    raise HardwareKeyError("YubiKey returned a non-RSA public key.")
                return pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        except HardwareKeyError:
            raise
        except Exception as exc:
            raise HardwareKeyError(
                f"YubiKey PIV key generation failed on slot {target_slot}: {exc}"
            ) from exc

    def decrypt_oaep(
        self,
        ciphertext: bytes,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> bytes:
        """Perform hardware RSA-OAEP-SHA256 decryption on the YubiKey PIV slot."""
        target_slot = self._resolve_slot(entity_id, slot)
        oaep = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
        try:
            with self._open_connection() as conn:
                session = PivSession(conn)
                if self.pin is not None:
                    session.verify_pin(self.pin)
                return session.decrypt(target_slot, ciphertext, oaep)
        except Exception as exc:
            raise HardwareKeyError(
                f"YubiKey PIV hardware decryption failed on slot {target_slot}: {exc}"
            ) from exc

    def get_decryptor(
        self,
        entity_id: bytes | None = None,
        slot: int | SLOT = SLOT.KEY_MANAGEMENT,
    ) -> Callable[[bytes], bytes]:
        """Return a callable `decrypt(ciphertext: bytes) -> bytes` bound to the slot."""
        return lambda ct: self.decrypt_oaep(ct, entity_id=entity_id, slot=slot)

