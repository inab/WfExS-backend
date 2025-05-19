import ssl
import types

from typing import (
    Any,
    Type,
)

from .host import FTPHost

SSLSocket: Type[ssl.SSLSocket] | None

class FTPFile:
    closed: bool
    def __init__(self, host: FTPHost) -> None: ...
    def __iter__(self) -> FTPFile: ...
    def __next__(self) -> str: ...
    def __enter__(self) -> FTPFile: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool: ...
    def __getattr__(self, attr_name: str) -> Any: ...
    def close(self) -> None: ...
