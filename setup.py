from setuptools import setup, find_packages

setup(
    name='dump_windows_secrets',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'smb @ git+ssh://git@github.com/vphpersson/smb.git#egg=smb',
        'rpc @ git+ssh://git@github.com/vphpersson/rpc.git#egg=rpc',
        'ms_rrp @ git+ssh://git@github.com/vphpersson/ms_rrp.git#egg=ms_rrp',
        'ms_scmr @ git+ssh://git@github.com/vphpersson/ms_scmr.git#egg=ms_scmr',
        'msdsalgs @ git+ssh://git@github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
        'pyutils @ git+ssh://git@github.com/vphpersson/pyutils.git#egg=pyutils',
        'python-registry',
        'pycryptodome'
    ]
)
