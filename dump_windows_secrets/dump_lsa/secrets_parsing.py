from re import sub as re_sub, I as RE_I
from logging import getLogger

from rpc.connection import Connection as RPCConnection
from ms_scmr.operations.r_open_service_w import r_open_service_w, ROpenServiceWRequest, ServiceAccessFlagMask
from ms_scmr.operations.r_query_service_config_w import r_query_service_config_w, RQueryServiceConfigWRequest
from msdsalgs.win32_error import ErrorServiceDoesNotExistError


LOG = getLogger(__name__)


async def extract_service_passwords(
    rpc_connection: RPCConnection,
    sc_manager_handle: bytes,
    policy_secrets: dict[str, bytes]
) -> dict[str, str]:
    """

    :param rpc_connection:
    :param sc_manager_handle:
    :param policy_secrets:
    :return:
    """

    service_name_to_password: dict[str, str] = {
        re_sub(pattern=r'^_SC_', repl='', string=key, flags=RE_I): value.decode(encoding='utf-16-le')
        for key, value in policy_secrets.items()
        if key.upper().startswith('_SC_')
    }

    account_name_to_password: dict[str, str] = {}

    for service_name, password in service_name_to_password.items():
        account_name: str = f'({service_name})'

        if not service_name.lower().endswith('_history'):
            try:
                r_open_service_w_options = dict(
                    rpc_connection=rpc_connection,
                    request=ROpenServiceWRequest(
                        sc_manager_handle=sc_manager_handle,
                        service_name=service_name,
                        desired_access=ServiceAccessFlagMask(service_query_config=True)
                    )
                )
                async with r_open_service_w(**r_open_service_w_options) as r_open_service_w_response:
                    account_name = (
                        await r_query_service_config_w(
                            rpc_connection=rpc_connection,
                            request=RQueryServiceConfigWRequest(
                                service_handle=r_open_service_w_response.service_handle
                            )
                        )
                    ).service_config.service_start_name
            except ErrorServiceDoesNotExistError as e:
                LOG.warning(f'{e} -- Service name: {service_name}.')

        account_name_to_password[account_name] = password

    return account_name_to_password
