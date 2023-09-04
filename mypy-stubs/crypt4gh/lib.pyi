from . import SEGMENT_SIZE as SEGMENT_SIZE, header as header
from .exceptions import close_on_broken_pipe as close_on_broken_pipe
from .header import CompoundKey

from collections.abc import Generator
from io import BytesIO
from logging import Logger
from pathlib import Path
from typing import (
    Callable,
    IO,
    Optional,
    Sequence,
    Tuple,
)

LOG: Logger
CIPHER_DIFF: int
CIPHER_SEGMENT_SIZE: int

def encrypt(
    keys: Sequence[CompoundKey],
    infile: IO[bytes],
    outfile: IO[bytes],
    offset: int = ...,
    span: Optional[int] = ...,
) -> None: ...
def cipher_chunker(f: IO[bytes], size: int) -> Generator[bytes, None, None]: ...
def decrypt_block(ciphersegment: bytes, session_keys: Sequence[bytes]) -> bytes: ...

class ProcessingOver(Exception): ...

def limited_output(
    offset: int = ...,
    limit: Optional[int] = ...,
    process: Optional[Callable[[bytes], None]] = ...,
) -> Generator[None, bytes, None]: ...
def body_decrypt(
    infile: IO[bytes],
    session_keys: Sequence[bytes],
    output: Generator[None, bytes, None],
    offset: int,
) -> None: ...

class DecryptedBuffer:
    fileobj: IO[bytes]
    session_keys: Sequence[bytes]
    buf: BytesIO
    block: int
    output: Generator[None, bytes, None]
    def __init__(
        self,
        fileobj: IO[bytes],
        session_keys: Sequence[bytes],
        output: Generator[None, bytes, None],
    ) -> None: ...
    def buf_size(self) -> int: ...
    def skip(self, size: int) -> None: ...
    def read(self, size: int) -> None: ...

def body_decrypt_parts(
    infile: IO[bytes],
    session_keys: Sequence[bytes],
    output: Generator[None, bytes, None],
    edit_list: Optional[Sequence[int]] = ...,
) -> None: ...
def decrypt(
    keys: Sequence[CompoundKey],
    infile: IO[bytes],
    outfile: IO[bytes],
    sender_pubkey: Optional[bytes] = ...,
    offset: int = ...,
    span: Optional[int] = ...,
) -> None: ...
def reencrypt(
    keys: Sequence[CompoundKey],
    recipient_keys: Sequence[CompoundKey],
    infile: IO[bytes],
    outfile: IO[bytes],
    chunk_size: int = ...,
    trim: bool = ...,
) -> None: ...
def rearrange(
    keys: Sequence[CompoundKey],
    infile: IO[bytes],
    outfile: IO[bytes],
    offset: int = ...,
    span: Optional[int] = ...,
) -> None: ...
