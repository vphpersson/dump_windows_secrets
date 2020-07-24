from hashlib import md5

from Crypto.Cipher import ARC4
from msdsalgs.crypto import decrypt_aes

from dump_sam.structures.domain_account_f import DomainAccountF
from dump_sam.structures.sam import SamKeyDataAes, SamKeyData

QWERTY = b'!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0'
DIGITS = b'0123456789012345678901234567890123456789\0'


def obtain_rc4_encryption_key(f_salt_value: bytes, bootkey: bytes) -> bytes:
    """
    :param f_salt_value:
    :param bootkey:
    :return:
    """

    return md5(f_salt_value + QWERTY + bootkey + DIGITS).digest()


def obtain_hashed_bootkey_rc4(
    bootkey: bytes,
    f_salt_value: bytes,
    f_key_value: bytes,
    f_checksum_value: bytes
):
    """
    :param bootkey:
    :param f_salt_value:
    :param f_key_value:
    :param f_checksum_value:
    :return:
    """

    return ARC4.new(
        key=obtain_rc4_encryption_key(f_salt_value=f_salt_value, bootkey=bootkey)
    ).encrypt(f_key_value + f_checksum_value)


def obtain_hashed_bootkey(domain_account_f: DomainAccountF, bootkey: bytes) -> bytes:
    """
    :param domain_account_f:
    :param bootkey:
    :return:
    """

    # TODO: Add `is_blabla` method to `DomainAccountF`.
    if domain_account_f.key_0[0] == 1:
        sam_key_data = SamKeyData.from_bytes(domain_account_f.key_0)

        hashed_boot_key = obtain_hashed_bootkey_rc4(
            bootkey,
            sam_key_data.salt,
            sam_key_data.key,
            sam_key_data.checksum
        )

        # Verify key with checksum.
        check_sum = md5(hashed_boot_key[:16] + DIGITS + hashed_boot_key[:16] + QWERTY).digest()

        # TODO: This error has been raised several times on Windows 10 machines when run
        #   "First introduced on Windows NT 4.0 SP3, it was removed in Windows 10 and Windows Server 2016"
        #   ... this should entail that Syskey is not what causes the check to fail on Windows 10 systems. :thinking:
        if check_sum != hashed_boot_key[16:]:
            raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

        return hashed_boot_key

    elif domain_account_f.key_0[0] == 2:
        # This is Windows 2016 TP5 on in theory (it is reported that some W10 and 2012R2 might behave this way also)
        sam_key_data = SamKeyDataAes.from_bytes(domain_account_f.key_0)
        return decrypt_aes(
            bootkey,
            sam_key_data.data,
            sam_key_data.salt
        )
    else:
        # TODO: Add a proper exception.
        raise ValueError
