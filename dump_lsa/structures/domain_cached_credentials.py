from dataclasses import dataclass


@dataclass
class DomainCachedCredentials:
    dns_domain_name: str
    username: str
    encrypted_hash: bytes

    def __str__(self) -> str:
        # TODO: Not sure about the data after the ":". On the hashcat example page, that field consists of only
        #  integers.
        return f'{self.encrypted_hash.hex()}:{self.username}'


@dataclass
class DomainCachedCredentials2:
    iteration_count: int
    dns_domain_name: str
    username: str
    encrypted_hash: bytes

    def __str__(self) -> str:
        return f'$DCC2${self.iteration_count}#{self.dns_domain_name}\\{self.username}#{self.encrypted_hash.hex()}'
