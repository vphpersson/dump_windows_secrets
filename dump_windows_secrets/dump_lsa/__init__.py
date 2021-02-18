from dump_windows_secrets.dump_lsa.structures.domain_cached_credentials import DomainCachedCredentials2
from dump_windows_secrets.dump_lsa.structures.lsa_secret import LSASecret
from dump_windows_secrets.dump_lsa.key_extraction import get_encrypted_policy_secrets_encryption_key
from dump_windows_secrets.dump_lsa.secrets_extraction import get_security_policy_secrets, get_domain_cached_credentials
from Registry.Registry import Registry


def dump_lsa_secrets(
    security_registry: Registry,
    boot_key: bytes
) -> tuple[list[DomainCachedCredentials2], dict[str, bytes]]:
    """

    :param security_registry:
    :param boot_key:
    :return:
    """

    encrypted_policy_secrets_encryption_key, use_new_style = get_encrypted_policy_secrets_encryption_key(
        security_registry
    )
    policy_secrets_encryption_key = LSASecret.from_bytes(
        data=encrypted_policy_secrets_encryption_key
    ).blob(decryption_key=boot_key).secret[52:84]

    policy_secrets: dict[str, bytes] = get_security_policy_secrets(
        security_registry=security_registry,
        policy_secrets_decryption_key=policy_secrets_encryption_key,
        use_new_style=use_new_style
    )

    domain_cached_credentials: list[DomainCachedCredentials2] = get_domain_cached_credentials(
        security_registry=security_registry,
        cached_credentials_decryption_key=policy_secrets['NL$KM'][:16],
        use_new_style=use_new_style
    )

    return domain_cached_credentials, policy_secrets
