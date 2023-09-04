from . import SEGMENT_SIZE as SEGMENT_SIZE, VERSION as VERSION

from collections.abc import Generator
from itertools import chain as chain

from logging import Logger
from typing import (
    IO,
    Iterable,
    Optional,
    Sequence,
    Tuple,
)

from typing_extensions import (
    Protocol,
)

class ToBytesProto(Protocol):
    def to_bytes(self, value: int, encoding: str) -> bytes: ...

CompoundKey = Tuple[int, bytes] | Tuple[int, bytes, Optional[bytes]]

LOG: Logger
MAGIC_NUMBER: bytes

def parse(stream: IO[bytes]) -> Generator[bytes, None, None]: ...
def serialize(packets: Iterable[bytes]) -> bytes: ...

PACKET_TYPE_DATA_ENC: bytes
PACKET_TYPE_EDIT_LIST: bytes

def partition_packets(
    packets: Iterable[bytes],
) -> Tuple[Sequence[bytes], Optional[bytes]]: ...
def make_packet_data_enc(
    encryption_method: ToBytesProto, session_key: bytes
) -> bytes: ...
def parse_enc_packet(packet: bytes) -> bytes: ...
def make_packet_data_edit_list(edit_list: Iterable[bytes]) -> bytes: ...
def validate_edit_list(edits: Sequence[int]) -> None: ...
def parse_edit_list_packet(packet: bytes) -> Sequence[int]: ...
def encrypt_X25519_Chacha20_Poly1305(
    data: bytes, seckey: bytes, recipient_pubkey: bytes
) -> bytes: ...
def decrypt_X25519_Chacha20_Poly1305(
    encrypted_part: bytes, privkey: bytes, sender_pubkey: Optional[bytes] = ...
) -> bytes: ...
def decrypt_packet(
    packet: bytes, keys: Sequence[CompoundKey], sender_pubkey: Optional[bytes] = ...
) -> Optional[bytes]: ...
def encrypt(
    packet: bytes, keys: Sequence[CompoundKey]
) -> Generator[bytes, None, None]: ...
def decrypt(
    encrypted_packets: Iterable[bytes],
    keys: Sequence[CompoundKey],
    sender_pubkey: Optional[bytes] = ...,
) -> Tuple[Sequence[bytes], Sequence[bytes]]: ...
def deconstruct(
    infile: IO[bytes], keys: Sequence[CompoundKey], sender_pubkey: Optional[bytes] = ...
) -> Tuple[Sequence[bytes], Optional[Sequence[int]]]: ...
def reencrypt(
    header_packets: Iterable[bytes],
    keys: Sequence[CompoundKey],
    recipient_keys: Sequence[CompoundKey],
    trim: bool = ...,
) -> Sequence[bytes]: ...
def rearrange(
    header_packets: Iterable[bytes],
    keys: Sequence[CompoundKey],
    offset: int = ...,
    span: Optional[int] = ...,
    sender_pubkey: Optional[bytes] = ...,
) -> Tuple[Sequence[bytes], Generator[bool, None, None]]: ...
