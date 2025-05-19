import os
from ftputil import FTPHost as FTPHost

from typing import (
    IO,
    Any,
)

__all__ = ["FTPHost", "LocalHost", "Syncer"]

class LocalHost:
    def open(
        self, path: str | bytes | os.PathLike[str] | os.PathLike[bytes], mode: int
    ) -> IO[bytes]: ...
    def time_shift(self) -> float: ...
    def __getattr__(self, attr: str) -> Any: ...

class Syncer:
    def __init__(
        self, source: FTPHost | LocalHost, target: FTPHost | LocalHost
    ) -> None: ...
    def sync(self, source_path: str, target_path: str) -> None: ...
