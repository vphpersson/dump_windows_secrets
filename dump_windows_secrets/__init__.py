from typing import Iterable

from pyutils.my_string import underline, text_align_delimiter
from rpc.connection import Connection as RPCConnection
from smb.v2.session import Session as SMBv2Session
from ms_scmr.operations.r_open_sc_manager_w import r_open_sc_manager_w, ROpenSCManagerWRequest
from ms_scmr import MS_SCMR_PIPE_NAME, MS_SCMR_ABSTRACT_SYNTAX
from rpc.structures.context_list import ContextList
from rpc.structures.context_element import ContextElement

from dump_windows_secrets.dump_sam import SAMEntry
from dump_windows_secrets.dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials2
from dump_windows_secrets.dump_lsa.secrets_parsing import extract_service_passwords


def get_secrets_output_string(
    sam_entries: Iterable[SAMEntry] | None = None,
    domain_cached_credentials: Iterable[DomainCachedCredentials2] | None = None,
    policy_secrets: dict[str, bytes] | None = None,
    service_account_name_to_password: dict[str, str] | None = None
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


async def resolve_service_credentials_with_rpc_connection(
    rpc_connection: RPCConnection,
    policy_secrets: dict[str, bytes]
) -> dict[str, str]:
    r_open_sc_manager_w_options = dict(rpc_connection=rpc_connection, request=ROpenSCManagerWRequest())
    async with r_open_sc_manager_w(**r_open_sc_manager_w_options) as r_open_sc_manager_w_response:
        return await extract_service_passwords(
            rpc_connection=rpc_connection,
            sc_manager_handle=r_open_sc_manager_w_response.scm_handle,
            policy_secrets=policy_secrets
        )


async def resolve_service_credentials(smb_session: SMBv2Session, policy_secrets: dict[str, bytes]) -> dict[str, str]:
    async with smb_session.make_smbv2_transport(pipe=MS_SCMR_PIPE_NAME) as (r, w):
        async with RPCConnection(reader=r, writer=w) as rpc_connection:
            await rpc_connection.bind(
                presentation_context_list=ContextList([
                    ContextElement(context_id=0, abstract_syntax=MS_SCMR_ABSTRACT_SYNTAX)
                ])
            )

            return await resolve_service_credentials_with_rpc_connection(
                rpc_connection=rpc_connection,
                policy_secrets=policy_secrets
            )
