from __future__ import annotations
from dataclasses import dataclass
from functools import partial
from struct import unpack as struct_unpack


def get_bytes_data(bytes_data: bytes, offset: int, length: int) -> bytes:
    return bytes_data[offset:offset+length]


def get_bytes_data_str(bytes_data: bytes, offset: int, length: int) -> str:
    return get_bytes_data(bytes_data, offset, length).decode('utf-16le')


@dataclass
class UserAccountV:
    name: str
    full_name: str
    comment: str
    user_comment: str
    home_dir: str
    home_dir_connect: str
    script_path: str
    profile_path: str
    workstation: str
    hours_allowed: bytes
    encrypted_lm_hash: bytes
    encrypted_nt_hash: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> UserAccountV:
        """
        Deserialize a byte stream into a `UserAccountV` structure.

        :param data: The byte stream corresponding to the `UserAccountV` structure.
        :return: A `UserAccountV` structure.
        """

        get_bytes = partial(get_bytes_data, data[204:])
        get_str = partial(get_bytes_data_str, data[204:])
        return cls(
            name=get_str(*struct_unpack('<LL', data[12:20])),
            full_name=get_str(*struct_unpack('<LL', data[24:32])),
            comment=get_str(*struct_unpack('<LL', data[36:44])),
            user_comment=get_str(*struct_unpack('<LL', data[48:56])),
            home_dir=get_str(*struct_unpack('<LL', data[72:80])),
            home_dir_connect=get_str(*struct_unpack('<LL', data[84:92])),
            script_path=get_str(*struct_unpack('<LL', data[96:104])),
            profile_path=get_str(*struct_unpack('<LL', data[108:116])),
            workstation=get_str(*struct_unpack('<LL', data[120:128])),
            hours_allowed=get_bytes(*struct_unpack('<LL', data[132:140])),
            encrypted_lm_hash=get_bytes(*struct_unpack('<LL', data[156:164])),
            encrypted_nt_hash=get_bytes(*struct_unpack('<LL', data[168:176])),
        )
