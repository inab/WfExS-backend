from . import PROG as PROG, SEGMENT_SIZE as SEGMENT_SIZE, header as header
from .keys import get_private_key as get_private_key, get_public_key as get_public_key
from .lib import CIPHER_DIFF as CIPHER_DIFF

from logging import Logger
from typing import (
    Any,
    Mapping,
    Optional,
    Sequence,
)

LOG: Logger
DEFAULT_SK: Optional[str]
DEFAULT_LOG: Optional[str]
__doc__: str

def parse_args(argv: Sequence[str] = ...) -> Mapping[str, Any]: ...
def output(args: Mapping[str, Any]) -> None: ...
def main(argv: Sequence[str] = ...) -> None: ...
