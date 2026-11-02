"""Declarative fixed-size binary object and multi-dimensional array serialization."""

from __future__ import annotations

from abc import ABC, abstractmethod
import math
import struct
from typing import Any, ClassVar, Self

from pybindb.constants import TYPE_TAG_LENGTH
from pybindb.exceptions import SerializationError

PRIMITIVE_FORMAT_MAP: dict[str, str] = {
    "i8": "b",
    "int8": "b",
    "b": "b",
    "u8": "B",
    "uint8": "B",
    "B": "B",
    "i16": "h",
    "int16": "h",
    "h": "h",
    "u16": "H",
    "uint16": "H",
    "H": "H",
    "i32": "i",
    "int32": "i",
    "i": "i",
    "u32": "I",
    "uint32": "I",
    "I": "I",
    "i64": "q",
    "int64": "q",
    "q": "q",
    "u64": "Q",
    "uint64": "Q",
    "Q": "Q",
    "f32": "f",
    "float32": "f",
    "f": "f",
    "f64": "d",
    "float64": "d",
    "d": "d",
    "bool": "?",
    "?": "?",
}


class TypeRegistry:
    """Global registry mapping 16-byte ASCII TYPE_TAG strings to BinarySerializable classes."""

    _registry: ClassVar[dict[str, type[BinarySerializable]]] = {}

    @classmethod
    def register(cls, model_cls: type[BinarySerializable]) -> None:
        tag = getattr(model_cls, "TYPE_TAG", None) or model_cls.__name__
        try:
            encoded = tag.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SerializationError(f"TYPE_TAG {tag!r} must be ASCII.") from exc
        if len(encoded) > TYPE_TAG_LENGTH:
            raise SerializationError(
                f"TYPE_TAG {tag!r} exceeds maximum length of {TYPE_TAG_LENGTH} bytes."
            )
        cls._registry[tag] = model_cls

    @classmethod
    def get(cls, tag: str) -> type[BinarySerializable]:
        cleaned = tag.rstrip("\x00")
        if cleaned not in cls._registry:
            raise SerializationError(
                f"Unregistered BinarySerializable TYPE_TAG: {cleaned!r}."
            )
        return cls._registry[cleaned]

    @classmethod
    def all_types(cls) -> dict[str, type[BinarySerializable]]:
        return dict(cls._registry)


class FieldDescriptor(ABC):
    """Abstract base descriptor for a fixed-size binary field."""

    name: str

    def __set_name__(self, owner: type[Any], name: str) -> None:
        self.name = name

    def __get__(self, instance: Any, owner: type[Any] | None = None) -> Any:
        if instance is None:
            return self
        return instance.__dict__.get(self.name)

    def __set__(self, instance: Any, value: Any) -> None:
        instance.__dict__[self.name] = self.normalize(value)

    @property
    @abstractmethod
    def byte_size(self) -> int:
        """Exact byte size of this field when serialized."""

    @property
    def struct_token(self) -> str | None:
        """Optional struct format token (without endian prefix) for fast compiled packing."""
        return None

    def normalize(self, value: Any) -> Any:
        """Validate/coerce a Python value when assigned to the attribute."""
        return value

    @abstractmethod
    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        """Pack `value` into `buf` at `offset`."""

    @abstractmethod
    def unpack_from(self, buf: memoryview, offset: int) -> Any:
        """Unpack value from `buf` at `offset`."""


class PrimitiveField(FieldDescriptor):
    """Fixed-size primitive numeric or boolean field backed by `struct`."""

    def __init__(self, fmt: str) -> None:
        cleaned = fmt.lstrip("<")
        if cleaned not in PRIMITIVE_FORMAT_MAP:
            raise SerializationError(
                f"Unsupported PrimitiveField format {fmt!r}. "
                f"Supported: {sorted(set(PRIMITIVE_FORMAT_MAP.keys()))}"
            )
        self.fmt_name = fmt
        self.struct_char = PRIMITIVE_FORMAT_MAP[cleaned]
        self._struct = struct.Struct("<" + self.struct_char)

    @property
    def byte_size(self) -> int:
        return self._struct.size

    @property
    def struct_token(self) -> str:
        return self.struct_char

    def normalize(self, value: Any) -> Any:
        if self.struct_char == "?":
            return bool(value)
        if self.struct_char in ("f", "d"):
            return float(value)
        return int(value)

    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        try:
            self._struct.pack_into(buf, offset, self.normalize(value))
        except Exception as exc:
            raise SerializationError(
                f"Failed to pack field {getattr(self, 'name', '<primitive>')} ({self.fmt_name}): {exc}"
            ) from exc

    def unpack_from(self, buf: memoryview, offset: int) -> Any:
        (val,) = self._struct.unpack_from(buf, offset)
        return val


class StringField(FieldDescriptor):
    """Fixed-length null-padded string field."""

    def __init__(self, length: int, encoding: str = "utf-8") -> None:
        if length <= 0:
            raise ValueError("StringField length must be > 0.")
        self.length = length
        self.encoding = encoding

    @property
    def byte_size(self) -> int:
        return self.length

    @property
    def struct_token(self) -> str:
        return f"{self.length}s"

    def normalize(self, value: Any) -> str:
        if isinstance(value, (bytes, bytearray, memoryview)):
            s = bytes(value).rstrip(b"\x00").decode(self.encoding)
        elif isinstance(value, str):
            s = value
        else:
            raise SerializationError(f"Expected str for StringField, got {type(value).__name__}.")
        encoded = s.encode(self.encoding)
        if len(encoded) > self.length:
            raise SerializationError(
                f"String {s!r} encoded length ({len(encoded)}) exceeds StringField({self.length})."
            )
        return s

    def encode_raw(self, value: Any) -> bytes:
        s = self.normalize(value)
        return s.encode(self.encoding).ljust(self.length, b"\x00")

    def decode_raw(self, raw: bytes) -> str:
        return raw.rstrip(b"\x00").decode(self.encoding)

    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        buf[offset : offset + self.length] = self.encode_raw(value)

    def unpack_from(self, buf: memoryview, offset: int) -> str:
        return self.decode_raw(bytes(buf[offset : offset + self.length]))


class HexBytesField(FieldDescriptor):
    """Fixed-length raw bytes or hex-encoded tag converted to exact `length` bytes."""

    def __init__(self, length: int) -> None:
        if length <= 0:
            raise ValueError("HexBytesField length must be > 0.")
        self.length = length

    @property
    def byte_size(self) -> int:
        return self.length

    @property
    def struct_token(self) -> str:
        return f"{self.length}s"

    def normalize(self, value: Any) -> bytes:
        if isinstance(value, str):
            hex_str = value.strip()
            if hex_str.startswith(("0x", "0X")):
                hex_str = hex_str[2:]
            if len(hex_str) % 2 == 1:
                hex_str = "0" + hex_str
            try:
                raw = bytes.fromhex(hex_str)
            except ValueError as exc:
                raise SerializationError(
                    f"Invalid hex string {value!r} for HexBytesField({self.length})."
                ) from exc
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
        else:
            raise SerializationError(
                f"Expected bytes or hex str for HexBytesField, got {type(value).__name__}."
            )

        if len(raw) > self.length:
            raise SerializationError(
                f"HexBytesField value length ({len(raw)}) exceeds configured length ({self.length})."
            )
        if len(raw) < self.length:
            raw = raw.ljust(self.length, b"\x00")
        return raw

    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        buf[offset : offset + self.length] = self.normalize(value)

    def unpack_from(self, buf: memoryview, offset: int) -> bytes:
        return bytes(buf[offset : offset + self.length])


class StructField(FieldDescriptor):
    """Descriptor wrapping a nested `BinarySerializable` subclass."""

    def __init__(self, model_cls: type[BinarySerializable]) -> None:
        if not (isinstance(model_cls, type) and issubclass(model_cls, BinarySerializable)):
            raise TypeError("StructField requires a BinarySerializable subclass.")
        self.model_cls = model_cls

    @property
    def byte_size(self) -> int:
        return self.model_cls.byte_size()

    def normalize(self, value: Any) -> BinarySerializable:
        if isinstance(value, self.model_cls):
            return value
        if isinstance(value, dict):
            return self.model_cls(**value)
        raise SerializationError(
            f"Expected {self.model_cls.__name__} instance, got {type(value).__name__}."
        )

    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        inst = self.normalize(value)
        raw = inst.to_bytes()
        buf[offset : offset + len(raw)] = raw

    def unpack_from(self, buf: memoryview, offset: int) -> BinarySerializable:
        size = self.byte_size
        return self.model_cls.from_bytes(buf[offset : offset + size])


def _flatten_nd(seq: Any, shape: tuple[int, ...], dim: int = 0) -> list[Any]:
    """Recursively validate shape and flatten an ND nested sequence into a 1D list."""
    expected_len = shape[dim]
    if not isinstance(seq, (list, tuple)) and hasattr(seq, "tolist"):
        seq = seq.tolist()
    if not isinstance(seq, (list, tuple)):
        raise SerializationError(
            f"Expected sequence of length {expected_len} at dimension {dim}, got {type(seq).__name__}."
        )
    if len(seq) != expected_len:
        raise SerializationError(
            f"Array dimension {dim} length mismatch: expected {expected_len}, got {len(seq)}."
        )
    if dim == len(shape) - 1:
        return list(seq)
    out: list[Any] = []
    for item in seq:
        out.extend(_flatten_nd(item, shape, dim + 1))
    return out


def _reshape_nd(flat: list[Any] | tuple[Any, ...], shape: tuple[int, ...]) -> list[Any]:
    """Reshape a flat list of elements into nested Python lists matching `shape`."""
    if len(shape) == 1:
        return list(flat)
    step = math.prod(shape[1:])
    return [
        _reshape_nd(flat[i * step : (i + 1) * step], shape[1:])
        for i in range(shape[0])
    ]


class ArrayField(FieldDescriptor):
    """Fixed-size 1D or multi-dimensional array of any FieldDescriptor or BinarySerializable."""

    def __init__(
        self,
        element_field: FieldDescriptor | type[BinarySerializable],
        shape: int | tuple[int, ...],
    ) -> None:
        if isinstance(element_field, type) and issubclass(element_field, BinarySerializable):
            self.element_field: FieldDescriptor = StructField(element_field)
        elif isinstance(element_field, FieldDescriptor):
            self.element_field = element_field
        else:
            raise TypeError(
                "ArrayField element_field must be a FieldDescriptor or BinarySerializable subclass."
            )

        if isinstance(shape, int):
            if shape <= 0:
                raise ValueError("ArrayField shape must be > 0.")
            self.shape: tuple[int, ...] = (shape,)
        else:
            if not shape or any(d <= 0 for d in shape):
                raise ValueError(f"Invalid ArrayField shape: {shape!r}.")
            self.shape = tuple(shape)

        self.total_elements: int = math.prod(self.shape)
        self._elem_size: int = self.element_field.byte_size

        # Compile numeric primitive arrays directly into a single contiguous struct format string (e.g., `<64f`)
        if isinstance(self.element_field, PrimitiveField):
            self._compiled_struct: struct.Struct | None = struct.Struct(
                f"<{self.total_elements}{self.element_field.struct_char}"
            )
        else:
            self._compiled_struct = None

    @property
    def compiled_struct_format(self) -> str | None:
        """Return the compiled struct format string (e.g. `<64f`) for numeric arrays."""
        return self._compiled_struct.format if self._compiled_struct is not None else None

    @property
    def byte_size(self) -> int:
        return self.total_elements * self._elem_size

    @property
    def struct_token(self) -> str | None:
        if isinstance(self.element_field, PrimitiveField):
            return f"{self.total_elements}{self.element_field.struct_char}"
        return None

    def normalize(self, value: Any) -> list[Any]:
        flat = _flatten_nd(value, self.shape)
        normalized_flat = [self.element_field.normalize(v) for v in flat]
        return _reshape_nd(normalized_flat, self.shape)

    def flatten(self, value: Any) -> list[Any]:
        flat = _flatten_nd(value, self.shape)
        return [self.element_field.normalize(v) for v in flat]

    def pack_into(self, buf: memoryview, offset: int, value: Any) -> None:
        flat = self.flatten(value)
        if self._compiled_struct is not None:
            self._compiled_struct.pack_into(buf, offset, *flat)
        else:
            pos = offset
            for item in flat:
                self.element_field.pack_into(buf, pos, item)
                pos += self._elem_size

    def unpack_from(self, buf: memoryview, offset: int) -> list[Any]:
        if self._compiled_struct is not None:
            flat = list(self._compiled_struct.unpack_from(buf, offset))
            return _reshape_nd(flat, self.shape)

        flat_items: list[Any] = []
        pos = offset
        for _ in range(self.total_elements):
            flat_items.append(self.element_field.unpack_from(buf, pos))
            pos += self._elem_size
        return _reshape_nd(flat_items, self.shape)


class BinarySerializable:
    """Declarative base class for fixed-size binary serializable Python objects."""

    TYPE_TAG: ClassVar[str] = ""
    _fields: ClassVar[list[tuple[str, FieldDescriptor]]] = []
    _byte_size: ClassVar[int] = 0
    _full_struct: ClassVar[struct.Struct | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        fields: list[tuple[str, FieldDescriptor]] = []

        # Inherit parent BinarySerializable fields first
        for base in reversed(cls.__mro__[1:]):
            if issubclass(base, BinarySerializable) and base is not BinarySerializable:
                for fname, fdesc in getattr(base, "_fields", []):
                    if not any(existing_name == fname for existing_name, _ in fields):
                        fields.append((fname, fdesc))

        # Collect fields declared on cls
        for attr_name, attr_val in list(cls.__dict__.items()):
            if isinstance(attr_val, FieldDescriptor):
                attr_val.name = attr_name
                fields = [(n, d) for n, d in fields if n != attr_name]
                fields.append((attr_name, attr_val))
            elif (
                isinstance(attr_val, type)
                and issubclass(attr_val, BinarySerializable)
                and attr_val is not BinarySerializable
            ):
                wrapped = StructField(attr_val)
                wrapped.name = attr_name
                setattr(cls, attr_name, wrapped)
                fields = [(n, d) for n, d in fields if n != attr_name]
                fields.append((attr_name, wrapped))

        cls._fields = fields
        cls._byte_size = sum(f.byte_size for _, f in fields)

        if not cls.__dict__.get("TYPE_TAG"):
            cls.TYPE_TAG = cls.__name__[:TYPE_TAG_LENGTH]

        # Check if the entire struct can be compiled into a single struct.Struct
        tokens: list[str] = []
        all_primitive_or_fixed = True
        for _, fdesc in fields:
            tok = fdesc.struct_token
            if tok is None:
                all_primitive_or_fixed = False
                break
            tokens.append(tok)

        if all_primitive_or_fixed and tokens:
            cls._full_struct = struct.Struct("<" + "".join(tokens))
        else:
            cls._full_struct = None

        if fields:
            TypeRegistry.register(cls)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if len(args) > len(self._fields):
            raise TypeError(
                f"{self.__class__.__name__}() takes at most {len(self._fields)} positional arguments "
                f"({len(args)} given)."
            )
        assigned: set[str] = set()
        for (fname, _), val in zip(self._fields, args):
            setattr(self, fname, val)
            assigned.add(fname)

        for fname, val in kwargs.items():
            if fname in assigned:
                raise TypeError(
                    f"{self.__class__.__name__}() got multiple values for argument {fname!r}."
                )
            if not any(n == fname for n, _ in self._fields):
                raise TypeError(
                    f"{self.__class__.__name__}() got an unexpected keyword argument {fname!r}."
                )
            setattr(self, fname, val)
            assigned.add(fname)

        missing = [n for n, _ in self._fields if n not in assigned]
        if missing:
            raise TypeError(
                f"{self.__class__.__name__}() missing required field(s): {', '.join(missing)}"
            )

    @classmethod
    def byte_size(cls) -> int:
        """Return the exact serialized byte size of this class."""
        return cls._byte_size

    def to_bytes(self) -> bytes:
        """Serialize this instance into a fixed-size binary buffer of `byte_size()` bytes."""
        buf = bytearray(self._byte_size)
        mv = memoryview(buf)
        offset = 0
        for fname, fdesc in self._fields:
            val = getattr(self, fname)
            fdesc.pack_into(mv, offset, val)
            offset += fdesc.byte_size
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes | memoryview) -> Self:
        """Deserialize an instance of `cls` from `data`."""
        mv = memoryview(data)
        if len(mv) != cls._byte_size:
            raise SerializationError(
                f"{cls.__name__}.from_bytes() expected {cls._byte_size} bytes, got {len(mv)}."
            )
        kwargs: dict[str, Any] = {}
        offset = 0
        for fname, fdesc in cls._fields:
            kwargs[fname] = fdesc.unpack_from(mv, offset)
            offset += fdesc.byte_size
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        """Convert this instance into a plain dictionary of field values."""
        out: dict[str, Any] = {}
        for fname, _ in self._fields:
            val = getattr(self, fname)
            if isinstance(val, BinarySerializable):
                out[fname] = val.to_dict()
            else:
                out[fname] = val
        return out

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return all(
            getattr(self, fname) == getattr(other, fname) for fname, _ in self._fields
        )

    def __repr__(self) -> str:
        field_strs = ", ".join(
            f"{fname}={getattr(self, fname)!r}" for fname, _ in self._fields
        )
        return f"{self.__class__.__name__}({field_strs})"

