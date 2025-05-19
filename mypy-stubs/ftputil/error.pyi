import types
from typing import (
    Any,
)

__all__ = [
    "CommandNotImplementedError",
    "FTPIOError",
    "FTPOSError",
    "InaccessibleLoginDirError",
    "InternalError",
    "KeepAliveError",
    "NoEncodingError",
    "ParserError",
    "PermanentError",
    "RootDirError",
    "SyncError",
    "TemporaryError",
    "TimeShiftError",
]

class FTPError(Exception):
    strerror: str
    errno: int | None
    file_name: str | None
    def __init__(self, *args: Any, original_error: str | None = None) -> None: ...

class InternalError(FTPError): ...
class RootDirError(InternalError): ...
class InaccessibleLoginDirError(InternalError): ...
class TimeShiftError(InternalError): ...
class ParserError(InternalError): ...
class CacheMissError(InternalError): ...
class NoEncodingError(InternalError): ...
class KeepAliveError(InternalError): ...
class FTPOSError(FTPError, OSError): ...  # type: ignore[misc]
class TemporaryError(FTPOSError): ...
class PermanentError(FTPOSError): ...
class CommandNotImplementedError(PermanentError): ...
class RecursiveLinksError(PermanentError): ...
class SyncError(PermanentError): ...

class FtplibErrorToFTPOSError:
    def __enter__(self) -> None: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None: ...

class FTPIOError(FTPError, IOError): ...  # type: ignore[misc]

class FtplibErrorToFTPIOError:
    def __enter__(self) -> None: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None: ...
