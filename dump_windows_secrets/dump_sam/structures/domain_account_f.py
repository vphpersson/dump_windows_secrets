from __future__ import annotations
from datetime import datetime
from dataclasses import dataclass
from struct import unpack as struct_unpack

from msdsalgs.time import filetime_to_datetime


@dataclass
class DomainAccountF:
    revision: int
    creation_time: datetime
    domain_modified_count: int
    max_password_age: int
    min_password_age: int
    forced_logoff: int
    lockout_duration: int
    lockout_observation_window: int
    modified_count_at_last_promotion: int
    next_rid: int
    password_properties: int
    min_password_length: int
    password_history_length: int
    lockout_threshold: int
    server_state: int
    server_role: int
    uas_compatibility_required: int
    key_0: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> DomainAccountF:
        """
        :param data:
        :return:
        """

        # TODO: Have some of these be of type `timedelta`.
        return cls(
            revision=struct_unpack('<L', data[0:4])[0],
            creation_time=filetime_to_datetime(struct_unpack('<Q', data[8:16])[0]),
            domain_modified_count=struct_unpack('<Q', data[16:24])[0],
            max_password_age=struct_unpack('<Q', data[24:32])[0],
            min_password_age=struct_unpack('<Q', data[32:40])[0],
            forced_logoff=struct_unpack('<Q', data[40:48])[0],
            lockout_duration=struct_unpack('<Q', data[48:56])[0],
            lockout_observation_window=struct_unpack('<Q', data[56:64])[0],
            modified_count_at_last_promotion=struct_unpack('<Q', data[64:72])[0],
            next_rid=struct_unpack('<L', data[72:76])[0],
            password_properties=struct_unpack('<L', data[76:80])[0],
            min_password_length=struct_unpack('<H', data[80:82])[0],
            password_history_length=struct_unpack('<H', data[82:84])[0],
            lockout_threshold=struct_unpack('<H', data[84:86])[0],
            server_state=struct_unpack('<L', data[88:92])[0],
            server_role=struct_unpack('<H', data[92:94])[0],
            uas_compatibility_required=struct_unpack('<H', data[94:96])[0],
            key_0=data[104:]
        )
