from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack


@dataclass
class SamKeyData:
    revision: int
    length: int
    salt: bytes
    key: bytes
    checksum: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SamKeyData:
        return cls(
            revision=struct_unpack('<L', data[0:4])[0],
            length=struct_unpack('<L', data[4:8])[0],
            salt=data[8:24],
            key=data[24:40],
            checksum=data[40:56]
        )


@dataclass
class SamKeyDataAes:
    revision: int
    length: int
    # _checksum_length: int
    # _data_length: int
    salt: bytes
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SamKeyDataAes:

        data_len = struct_unpack('<L', data[12:16])[0]

        # TODO: Could it be that this struct is always 64 bytes?

        return cls(
            revision=struct_unpack('<L', data[0:4])[0],
            length=struct_unpack('<L', data[4:8])[0],
            salt=data[16:32],
            data=data[32:32+data_len]
            # _checksum_length=struct_unpack('<L', data[8:12])[0],
            # _data_length=struct_unpack('<L', data[12:16])[0]
        )


@dataclass
class SamHash:
    pek_id: int
    revision: int
    hash: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SamHash:
        return cls(
            pek_id=struct_unpack('<H', data[0:2])[0],
            revision=struct_unpack('<H', data[2:4])[0],
            hash=data[4:20]
        )


@dataclass
class SamHashAes:
    pek_id: int
    revision: int
    salt: bytes
    hash: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SamHashAes:
        return cls(
            pek_id=struct_unpack('<H', data[0:2])[0],
            revision=struct_unpack('<H', data[2:4])[0],
            salt=data[8:24],
            # TODO: Not sure about length...
            hash=data[24:]
        )
