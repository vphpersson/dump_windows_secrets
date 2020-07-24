from __future__ import annotations
from dataclasses import dataclass
from typing import List, Union
from contextlib import suppress
from io import BytesIO

from Registry.Registry import Registry, RegistryValueNotFoundException

from dump_sam.structures.domain_account_f import DomainAccountF
from dump_sam.structures.user_account_v import UserAccountV
from dump_sam.key_extraction import obtain_hashed_bootkey
from dump_sam.secrets_extraction import obtain_hashes_for_rid


@dataclass
class SAMEntry:
    rid: int
    account_name: str
    password_hint: str
    lm_hash: Union[bytes, str]
    nt_hash: Union[bytes, str]


def dump_sam_secrets(sam_dump: bytes, boot_key: bytes) -> List[SAMEntry]:
    """
    Dump secrets from a SAM registry hive.
    The hashes are are stored in an double-encrypted format, and must first be decrypted.
    :param sam_dump: The SAM registry hive as a bytes.
    :param boot_key: The boot key as bytes.
    :return: A list of LM and NT hashes for each user in the SAM registry hive of the target host.
    """

    sam_registry = Registry(BytesIO(sam_dump))

    hashed_bootkey: bytes = obtain_hashed_bootkey(
        domain_account_f=DomainAccountF.from_bytes(
            data=sam_registry.open(r'SAM\Domains\Account').value('F').raw_data()
        ),
        bootkey=boot_key
    )

    sam_entries: List[SAMEntry] = []

    rid_strings = (
        value.name()
        for value in sam_registry.open(r'SAM\Domains\Account\Users').subkeys()
        if value.name() != 'Names'
    )

    for rid_string in rid_strings:
        user_account_v = UserAccountV.from_bytes(
            data=sam_registry.open(f'SAM\\Domains\\Account\\Users\\{rid_string}').value('V').raw_data()
        )

        lm_hash, nt_hash = obtain_hashes_for_rid(
            rid=int(rid_string, 16),
            double_encrypted_lm_hash=user_account_v.encrypted_lm_hash,
            double_encrypted_nt_hash=user_account_v.encrypted_nt_hash,
            hashed_bootkey=hashed_bootkey
        )

        password_hint = ''
        with suppress(RegistryValueNotFoundException):
            password_hint = sam_registry.open(
                path=f'SAM\\Domains\\Account\\Users\\{rid_string}'
            ).value('UserPasswordHint').raw_data().decode(encoding='utf-16le')

        sam_entries.append(
            SAMEntry(
                rid=int(rid_string, 16),
                account_name=user_account_v.name,
                password_hint=password_hint,
                lm_hash=lm_hash,
                nt_hash=nt_hash
            )
        )

    return sam_entries
