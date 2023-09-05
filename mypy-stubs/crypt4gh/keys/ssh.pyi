from ..exceptions import exit_on_invalid_passphrase as exit_on_invalid_passphrase
from .kdf import (
    derive_key as derive_key,
    EncodeProto,
)

from logging import Logger
from typing import (
    Callable,
    IO,
    Tuple,
)

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import Mode

LOG: Logger
MAGIC_WORD: bytes

def get_derived_key_length(ciphername: bytes) -> int: ...
def get_cipher(ciphername: bytes, derived_key: bytes) -> Cipher[Mode]: ...
def decode_string(stream: IO[bytes]) -> bytes: ...
def parse_private_key(
    stream: IO[bytes], callback: Callable[[], EncodeProto]
) -> Tuple[bytes, bytes]: ...
def get_public_key(line: bytes) -> bytes: ...
