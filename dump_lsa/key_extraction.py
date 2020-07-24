from typing import Tuple
from pathlib import PureWindowsPath

from Registry.Registry import Registry
from Registry.Registry import RegistryValueNotFoundException


LSA_KEY_NAMES = ('JD', 'Skew1', 'GBG', 'Data')
BOOT_KEY_PARTS_PATHS: Tuple[PureWindowsPath] = tuple(
    PureWindowsPath(f'SYSTEM\\CurrentControlSet\\Control\\Lsa\\{key}')
    for key in LSA_KEY_NAMES
)


def transform_untransformed_boot_key(untransformed_boot_key: bytes) -> bytes:
    """
    Produce a boot key from the concatenated registry values from which the boot key is derived.
    :param untransformed_boot_key: The concatenated, untransformed boot key parts from which the boot key is derived.
    :return: The boot key corresponding to the provided untransformed data.
    """

    boot_key: bytes = b''
    for transform_idx in [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]:
        # When indexing an individual byte in a stream, an `int` is returned.
        # To turn it into a byte, one must use `bytes()` and place the `int` in an array.
        boot_key += bytes([untransformed_boot_key[transform_idx]])

    return boot_key


def get_boot_key(lsa_registry: Registry, from_root: bool = False):

    return transform_untransformed_boot_key(
        untransformed_boot_key=bytes.fromhex(
            ''.join(
                lsa_registry.open(boot_key_path.name if not from_root else str(boot_key_path))._nkrecord.classname()
                for boot_key_path in BOOT_KEY_PARTS_PATHS
            )
        )
    )


def get_encrypted_policy_secrets_encryption_key(security_registry: Registry) -> Tuple[bytes, bool]:
    """
    :param security_registry:
    :return:
    """

    try:
        return security_registry.open(r'Policy\PolEKList').value('(default)').raw_data(), True
    except RegistryValueNotFoundException:
        pass

    try:
        return security_registry.open(r'Policy\PolSecretEncryptionKey').value('(default)').raw_data(), False
    except RegistryValueNotFoundException:
        pass

    # TODO: Add a proper exception.
    raise Exception
