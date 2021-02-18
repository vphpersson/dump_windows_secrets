from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack
from hashlib import sha256 as hashlib_sha256

from msdsalgs.crypto import decrypt_aes


@dataclass
class LSASecretBlob:
    # TODO: Not sure what this length corresponds to.
    length: int
    secret: bytes
    # TODO: Not sure what this is.
    remaining: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> LSASecretBlob:
        length = struct_unpack('<L', data[0:4])[0]

        return cls(
            length=length,
            secret=data[16:16+length],
            remaining=data[16+length:]
        )


@dataclass
class LSASecret:
    version: int
    encryption_key_id: bytes
    # TODO: Use enum?
    encryption_algorithm: int
    # TODO: Use enum?
    flags: int
    encrypted_blob_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> LSASecret:
        return cls(
            version=struct_unpack('<L', data[0:4])[0],
            encryption_key_id=data[4:20],
            encryption_algorithm=struct_unpack('<L', data[20:24])[0],
            flags=struct_unpack('<L', data[24:28])[0],
            encrypted_blob_data=data[28:]
        )

    def blob_data(self, decryption_key: bytes) -> bytes:
        return decrypt_aes(
            key=hashlib_sha256(decryption_key + self.encrypted_blob_data[:32] * 1000).digest(),
            value=self.encrypted_blob_data[32:]
        )

    def blob(self, decryption_key: bytes) -> LSASecretBlob:
        return LSASecretBlob.from_bytes(self.blob_data(decryption_key))


@dataclass
class LSASecretXP:
    length: int
    version: int
    secret: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> LSASecretXP:
        length = struct_unpack('<L', data[0:4])[0]

        return cls(
            length=length,
            version=struct_unpack('<L', data[4:8])[0],
            # TODO: Not sure if the length is the length of the secret or the total length of the structure.
            secret=data[8:8+length]
        )
