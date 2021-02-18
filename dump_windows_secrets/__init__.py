from typing import Optional, Iterable
from pyutils.my_string import underline, text_align_delimiter
from dump_windows_secrets.dump_sam import SAMEntry
from dump_windows_secrets.dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials2


def get_secrets_output_string(
    sam_entries: Optional[Iterable[SAMEntry]] = None,
    domain_cached_credentials: Optional[Iterable[DomainCachedCredentials2]] = None,
    policy_secrets: Optional[dict[str, bytes]] = None,
    service_account_name_to_password: Optional[dict[str, str]] = None
) -> str:

    return (
        '\n\n'.join(
            section
            for section in [
                text_align_delimiter(
                    text=(
                            f"{underline(string='SAM entries')}\n\n"
                            + (
                                '\n\n'.join(
                                    f'Account name: {sam_entry.account_name}\n'
                                    f'NT hash: {sam_entry.nt_hash.hex()}'
                                    for sam_entry in sam_entries if sam_entry.nt_hash is not None
                                )
                            )
                    ),
                    put_non_match_after_delimiter=False
                ) if sam_entries else None,
                text_align_delimiter(
                    text=(
                            f"{underline(string='Service credentials')}\n\n"
                            + (
                                '\n\n'.join(
                                    f'Account name: {account_name}\n'
                                    f'Password: {password}'
                                    for account_name, password in service_account_name_to_password.items()
                                )
                            )
                    ),
                    put_non_match_after_delimiter=False
                ) if service_account_name_to_password else None,
                text_align_delimiter(
                    text=(
                            f"{underline(string='Domain cached credentials')}\n\n"
                            + (
                                '\n'.join(
                                    str(domain_cached_credentials_entry)
                                    for domain_cached_credentials_entry in domain_cached_credentials
                                )
                            )
                    ),
                    put_non_match_after_delimiter=False
                ) if domain_cached_credentials else None,
                text_align_delimiter(
                    text=(
                            f"{underline(string='Policy secrets')}\n\n"
                            + (
                                '\n'.join(
                                    f'{key}: {value.hex()}' for key, value in policy_secrets.items()
                                )
                            )
                    ),
                    put_non_match_after_delimiter=False
                ) if policy_secrets else None,
            ]
            if section
        )
    )
