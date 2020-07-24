from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack


@dataclass
class RegistryCacheEntry:
    user_length: int
    domain_name_length: int
    effective_name_length: int
    full_name_length: int
    logon_script_name_length: int
    profile_path_length: int
    home_directory_length: int
    home_directory_drive_length: int
    user_id: int
    primary_group_id: int
    group_count: int
    logon_domain_name_length: int
    # TODO: Add datetime?
    last_write: bytes
    revision: int
    sid_count: int
    # TODO: Parse flags?
    flags: int
    logon_package_length: int
    dns_domain_name_length: int
    upn_length: int
    initialization_vector: bytes
    checksum: bytes
    encrypted_data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> RegistryCacheEntry:
        return cls(
            user_length=struct_unpack('<H', data[0:2])[0],
            domain_name_length=struct_unpack('<H', data[2:4])[0],
            effective_name_length=struct_unpack('<H', data[4:6])[0],
            full_name_length=struct_unpack('<H', data[6:8])[0],
            logon_script_name_length=struct_unpack('<H', data[8:10])[0],
            profile_path_length=struct_unpack('<H', data[10:12])[0],
            home_directory_length=struct_unpack('<H', data[12:14])[0],
            home_directory_drive_length=struct_unpack('<H', data[14:16])[0],
            user_id=struct_unpack('<L', data[16:20])[0],
            primary_group_id=struct_unpack('<L', data[20:24])[0],
            group_count=struct_unpack('<L', data[24:28])[0],
            logon_domain_name_length=struct_unpack('<H', data[28:30])[0],
            last_write=data[32:40],
            revision=struct_unpack('<L', data[40:44])[0],
            sid_count=struct_unpack('<L', data[44:48])[0],
            flags=struct_unpack('<L', data[48:52])[0],
            logon_package_length=struct_unpack('<L', data[56:60])[0],
            dns_domain_name_length=struct_unpack('<H', data[60:62])[0],
            upn_length=struct_unpack('<H', data[62:64])[0],
            initialization_vector=data[64:80],
            checksum=data[80:96],
            encrypted_data=data[96:]
        )
