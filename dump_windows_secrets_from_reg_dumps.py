#!/usr/bin/env python3

from io import BytesIO
from typing import Type

from Registry.Registry import Registry

from dump_windows_secrets.cli import DumpWindowsSecretsFromRegDumpsArgumentParser
from dump_windows_secrets.dump_lsa import dump_lsa_secrets
from dump_windows_secrets.dump_lsa.key_extraction import get_boot_key
from dump_windows_secrets.dump_sam import dump_sam_secrets, SAMEntry
from dump_windows_secrets import get_secrets_output_string


def main():
    args: Type[DumpWindowsSecretsFromRegDumpsArgumentParser.Namespace] = \
        DumpWindowsSecretsFromRegDumpsArgumentParser().parse_args()

    boot_key: bytes = get_boot_key(lsa_registry=Registry(BytesIO(args.system_dump_path.read_bytes())), from_root=True)

    domain_cached_credentials, policy_secrets = (None, None) if not args.security_dump_path else dump_lsa_secrets(
        security_registry=Registry(BytesIO(args.security_dump_path.read_bytes())),
        boot_key=boot_key
    )

    sam_entries: list[SAMEntry] | None = dump_sam_secrets(
        sam_dump=args.sam_dump_path.read_bytes(),
        boot_key=boot_key
    ) if args.sam_dump_path else None

    print(
        get_secrets_output_string(
            sam_entries=sam_entries,
            domain_cached_credentials=domain_cached_credentials,
            policy_secrets=policy_secrets
        )
    )


if __name__ == '__main__':
    main()
