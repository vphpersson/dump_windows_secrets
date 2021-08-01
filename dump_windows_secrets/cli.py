from typing import Optional
from pathlib import Path, PureWindowsPath

from pyutils.argparse.typed_argument_parser import TypedArgumentParser
from smb.contrib.argument_parsers import SmbSingleAuthenticationArgumentParser


# TODO: I want to use `TypedArgumentParser`...
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


class DumpWindowsSecretsFromRegDumpsArgumentParser(TypedArgumentParser):
    class Namespace:
        system_dump_path: Path
        security_dump_path: Optional[Path]
        sam_dump_path: Optional[Path]

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(dict(description='Extract Windows secrets from registry dump files.') | kwargs)
        )

        self.add_argument(
            'system_dump_path',
            type=Path,
            help='The path of a SYSTEM reg dump file.'
        )

        self.add_argument(
            '--security-dump-path',
            type=Path,
            help='The path of a SECURITY reg dump file.'
        )

        self.add_argument(
            '--sam-dump-path',
            type=Path,
            help='The path of a SAM reg dump file.'
        )
