from typing import (
    Mapping,
    Tuple,
)

from typing_extensions import (
    Protocol,
)

class EncodeProto(Protocol):
    def encode(self) -> bytes: ...

scrypt_supported: bool
KDFS: Mapping[bytes, Tuple[int, int]]

def get_kdf(kdfname: bytes) -> Tuple[int, int]: ...
def derive_key(
    alg: bytes, passphrase: bytes, salt: bytes, rounds: int, dklen: int = ...
) -> bytes: ...
