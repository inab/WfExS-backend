import types
from typing import (
    Any,
    IO,
    Sequence,
    Tuple,
)

import ftplib
from collections.abc import Generator

__all__ = ["FTPHost"]

class default_session_factory(ftplib.FTP):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

from .file import FTPFile
from .path import _Path
from .stat import (
    _Stat,
    StatResult,
    Parser,
)

class FTPHost:
    path: _Path
    stat_cache: _Stat
    closed: bool
    use_list_a_option: bool
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def keep_alive(self) -> None: ...
    def open(
        self,
        path: str,
        mode: str = "r",
        buffering: int | None = None,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        *,
        rest: int | None = None
    ) -> FTPFile: ...
    def close(self) -> None: ...
    def set_parser(self, parser: Parser) -> None: ...
    def set_time_shift(self, time_shift: float) -> None: ...
    def time_shift(self) -> float: ...
    def synchronize_times(self) -> None: ...
    @staticmethod
    def copyfileobj(
        source: IO[bytes],
        target: IO[bytes],
        max_chunk_size: int = ...,
        callback: Any | None = None,
    ) -> None: ...
    def upload(self, source: str, target: str, callback: Any | None = None) -> None: ...
    def upload_if_newer(
        self, source: str, target: str, callback: Any | None = None
    ) -> bool: ...
    def download(
        self, source: str, target: str, callback: Any | None = None
    ) -> None: ...
    def download_if_newer(
        self, source: str, target: str, callback: Any | None = None
    ) -> bool: ...
    def getcwd(self) -> str: ...
    def chdir(self, path: str) -> None: ...
    def mkdir(self, path: str, mode: int | None = None) -> None: ...
    def makedirs(
        self, path: str, mode: int | None = None, exist_ok: bool = False
    ) -> None: ...
    def rmdir(self, path: str) -> None: ...
    def remove(self, path: str) -> None: ...
    unlink = remove
    def rmtree(
        self, path: str, ignore_errors: bool = False, onerror: Any | None = None
    ) -> None: ...
    def rename(self, source: str, target: str) -> None: ...
    def listdir(self, path: str) -> Sequence[str]: ...
    def lstat(
        self, path: str, _exception_for_missing_path: bool = True
    ) -> StatResult: ...
    def stat(
        self, path: str, _exception_for_missing_path: bool = True
    ) -> StatResult: ...
    def walk(
        self,
        top: str,
        topdown: bool = True,
        onerror: str | None = None,
        followlinks: bool = False,
    ) -> Generator[Tuple[str, Sequence[str], Sequence[str]]]: ...
    def chmod(self, path: str, mode: int) -> None: ...
    def __enter__(self) -> FTPHost: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool: ...
