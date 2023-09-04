from logging import Logger
from pathlib import Path
from typing import (
    Callable,
    Optional,
    Sequence,
)
from . import c4gh as c4gh, ssh as ssh
from .kdf import EncodeProto

from base64 import b64encode as b64encode

LOG: Logger
DEFAULT_LOG: Optional[str]
DEFAULT_PK: str
DEFAULT_SK: str
# __doc__: str

def load_from_pem(filepath: str | Path) -> bytes: ...
def get_public_key(filepath: str | Path) -> bytes: ...
def get_private_key(
    filepath: str | Path, callback: Callable[[], EncodeProto]
) -> bytes: ...
def run(argv: Sequence[str] = ...) -> int: ...
def main(argv: Sequence[str] = ...) -> None: ...
