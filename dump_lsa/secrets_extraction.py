from struct import unpack as struct_unpack
from contextlib import suppress
from typing import List, Union, Dict

from msdsalgs.crypto import decrypt_aes
from Registry.Registry import Registry
from Registry.Registry import RegistryValueNotFoundException

from dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials, DomainCachedCredentials2
from dump_lsa.structures.lsa_secret import LSASecret
from dump_lsa.structures.registry_cache_entry import RegistryCacheEntry


def get_domain_cached_credentials(
    security_registry: Registry,
    cached_credentials_decryption_key: bytes,
    use_new_style: bool = True
) -> List[DomainCachedCredentials2]:
    iteration_count = 10240
    with suppress(RegistryValueNotFoundException):
        reg_iteration_count = struct_unpack('<L', security_registry.open(r'Cache').value('NL$IterationCount'))[0]
        iteration_count = reg_iteration_count & 0xfffffc00 if reg_iteration_count > 10240 else reg_iteration_count * 1024

    registry_cache_entries = (
        RegistryCacheEntry.from_bytes(cache_key.raw_data())
        for cache_key in security_registry.open('Cache').values()
        if cache_key.name() not in {'NL$Control', 'NL$IterationCount'}
    )

    domain_cached_credentials: List[Union[DomainCachedCredentials, DomainCachedCredentials2]] = list()

    for registry_cache_entry in registry_cache_entries:
        if registry_cache_entry.initialization_vector == b'\x00' * 16:
            continue

        # TODO: Make nicer? (and parse flags in class)?
        if registry_cache_entry.flags & 1 == 1:
            if use_new_style:
                decrypted_cached_entry_data = decrypt_aes(
                    key=cached_credentials_decryption_key,
                    value=registry_cache_entry.encrypted_data,
                    initialization_vector=registry_cache_entry.initialization_vector
                )
            else:
                raise NotImplementedError
                # TODO: For some reason impacket uses `encrypt()`. Confirm that `decrypt()` is correct.
                # decrypted_cached_entry_data = ARC4.new(
                #     key=HMAC.new(
                #         key=nlkm_key,
                #         msg=registry_cache_entry.initialization_vector,
                #     ).digest()
                # ).decrypt(ciphertext=registry_cache_entry.encrypted_data)
        else:
            # "Plain! Until we figure out what this is, we skip it"
            raise NotImplementedError

        def calc_padded_length(length: int) -> int:
            return length + (length & 0x3) if (length & 0x3) > 0 else length

        padded_user_length = calc_padded_length(registry_cache_entry.user_length)
        padded_domain_length = calc_padded_length(registry_cache_entry.domain_name_length)

        encrypted_hash = decrypted_cached_entry_data[:16]
        username = decrypted_cached_entry_data[72:72+registry_cache_entry.user_length].decode(encoding='utf-16le')
        dns_domain_name = decrypted_cached_entry_data[
            72+padded_user_length+padded_domain_length
            :
            72+padded_user_length+padded_domain_length+registry_cache_entry.dns_domain_name_length
        ].decode(encoding='utf-16le')

        if use_new_style:
            domain_cached_credentials.append(
                DomainCachedCredentials2(
                    iteration_count=iteration_count,
                    dns_domain_name=dns_domain_name,
                    username=username,
                    encrypted_hash=encrypted_hash
                )
            )
        else:
            domain_cached_credentials.append(
                DomainCachedCredentials(
                    dns_domain_name=dns_domain_name,
                    username=username,
                    encrypted_hash=encrypted_hash
                )
            )

    return domain_cached_credentials


def get_security_policy_secrets(
    security_registry: Registry,
    policy_secrets_decryption_key: bytes,
    use_new_style: bool = True
) -> Dict[str, bytes]:

    security_policy_secret_keys = (
        security_policy_key
        for security_policy_key in security_registry.open(r'Policy\Secrets').subkeys()
        if security_policy_key.name() != 'NL$Control'
    )

    secret_name_to_secret_data: Dict[str, bytes] = dict()

    for security_policy_secret_key in security_policy_secret_keys:
        for value_type in ('CurrVal', 'OldVal'):
            encrypted_secret_data = security_policy_secret_key.subkey(value_type).value('(default)').raw_data()
            if not encrypted_secret_data:
                continue

            if use_new_style:
                secret_data = LSASecret.from_bytes(
                    data=encrypted_secret_data
                ).blob(decryption_key=policy_secrets_decryption_key).secret
            else:
                raise NotImplementedError

            secret_name_to_secret_data[
                security_policy_secret_key.name() + ('_history' if value_type == 'OldVal' else '')
            ] = secret_data

    return secret_name_to_secret_data
