from setuptools import setup, find_packages

setup(
    name='dump_windows_secrets',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'smb @ git+https://github.com/vphpersson/smb.git#egg=smb',
        'rpc @ git+https://github.com/vphpersson/rpc.git#egg=rpc',
        'ms_rrp @ git+https://github.com/vphpersson/ms_rrp.git#egg=ms_rrp',
        'ms_scmr @ git+https://github.com/vphpersson/ms_scmr.git#egg=ms_scmr',
        'msdsalgs @ git+https://github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
        'typed_argument_parser @ git+https://github.com/vphpersson/typed_argument_parser.git#egg=typed_argument_parser',
        'string_utils_py @ git+https://github.com/vphpersson/string_utils_py.git#egg=string_utils_py',
        'python-registry',
        'pycryptodome'
    ]
)
