from typing import Tuple, Optional
from hashlib import md5
from struct import pack as struct_pack

from Crypto.Cipher import ARC4
from msdsalgs.crypto import decrypt_aes, DesEcbLmCipher

from dump_windows_secrets.dump_sam.structures.sam import SamHashAes, SamHash


# TODO: Add NTHash and LTHash typing classes?
def obtain_hashes_for_rid(
    rid: int,
    hashed_bootkey: bytes,
    double_encrypted_lm_hash: bytes,
    double_encrypted_nt_hash: bytes
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Decrypt the LM hash and NT hash for the account corresponding to the provided RID.
    :param rid: The RID of the account whose LM hash and NT hash to decrypt.
    :param hashed_bootkey:
    :param double_encrypted_lm_hash: The LM hash in a double-encrypted format.
    :param double_encrypted_nt_hash: The NT hash in a double-encrypted format.
    :return: The LM hash and NT hash for the account with the provided RID.
    """

    new_style = double_encrypted_nt_hash[2] != 0x1

    if new_style:
        # The double-encrypted hashes are encrypted with AES.

        lm_hash_aes = SamHashAes.from_bytes(double_encrypted_lm_hash)
        des_encrypted_lm_hash: bytes = decrypt_aes(
            key=hashed_bootkey[:0x10],
            value=lm_hash_aes.hash,
            initialization_vector=lm_hash_aes.salt
        )[:16]

        nt_hash_aes = SamHashAes.from_bytes(double_encrypted_nt_hash)
        des_encrypted_nt_hash: bytes = decrypt_aes(
            key=hashed_bootkey[:0x10],
            value=nt_hash_aes.hash,
            initialization_vector=nt_hash_aes.salt
        )[:16]
    else:
        # The double-encrypted hashes are encrypted with RC4.

        des_encrypted_lm_hash: bytes = ARC4.new(
            key=md5(hashed_bootkey[:0x10] + struct_pack('<L', rid) + b'LMPASSWORD\x00').digest()
        ).decrypt(
            ciphertext=SamHash.from_bytes(double_encrypted_lm_hash).hash
        )
        des_encrypted_nt_hash: bytes = ARC4.new(
            key=md5(hashed_bootkey[:0x10] + struct_pack('<L', rid) + b'NTPASSWORD\x00').digest()
        ).decrypt(
            ciphertext=SamHash.from_bytes(double_encrypted_nt_hash).hash
        )

    des_ecb_lm_cipher = DesEcbLmCipher.from_int_key(int_key=rid)

    return (
        des_ecb_lm_cipher.decrypt(encrypted_hash=des_encrypted_lm_hash) if des_encrypted_lm_hash else None,
        des_ecb_lm_cipher.decrypt(encrypted_hash=des_encrypted_nt_hash) if des_encrypted_nt_hash else None
    )
