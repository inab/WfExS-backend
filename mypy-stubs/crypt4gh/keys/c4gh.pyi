from ..exceptions import exit_on_invalid_passphrase as exit_on_invalid_passphrase
from .kdf import (
    EncodeProto,
    KDFS as KDFS,
    derive_key as derive_key,
    get_kdf as get_kdf,
    scrypt_supported as scrypt_supported,
)

from logging import Logger
from typing import (
    Callable,
    IO,
    Optional,
)

from nacl.public import PrivateKey

LOG: Logger
MAGIC_WORD: bytes

def encode_string(s: Optional[bytes]) -> bytes: ...
def decode_string(stream: IO[bytes]) -> bytes: ...
def encode_private_key(
    key: PrivateKey, passphrase: Optional[bytes], comment: Optional[bytes]
) -> bytes: ...
def generate(
    seckey: str,
    pubkey: str,
    passphrase: Optional[bytes] = ...,
    comment: Optional[bytes] = ...,
) -> None: ...
def parse_private_key(
    stream: IO[bytes], callback: Callable[[], EncodeProto]
) -> bytes: ...
