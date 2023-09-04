from . import PROG as PROG, lib as lib
from .keys import get_private_key as get_private_key, get_public_key as get_public_key

from logging import Logger
from typing import (
    Any,
    Mapping,
    Optional,
    Pattern,
    Sequence,
)

from typing_extensions import (
    Literal,
)

LOG: Logger
C4GH_DEBUG: str | Literal[False]
DEFAULT_SK: Optional[str]
DEFAULT_LOG: Optional[str]
__doc__: str

def parse_args(argv: Sequence[str] = ...) -> Mapping[str, Any]: ...

range_re: Pattern[str]

def parse_range(args: Mapping[str, Any]) -> Tuple[int, Optional[int]]: ...
def retrieve_private_key(args: Mapping[str, Any], generate: bool = ...) -> bytes: ...
def encrypt(args: Mapping[str, Any]) -> None: ...
def decrypt(args: Mapping[str, Any]) -> None: ...
def rearrange(args: Mapping[str, Any]) -> None: ...
def reencrypt(args: Mapping[str, Any]) -> None: ...
