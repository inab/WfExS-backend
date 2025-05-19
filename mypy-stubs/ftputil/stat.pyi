import os
from typing import (
    Any,
)

from .host import FTPHost

__all__ = ["StatResult", "Parser", "UnixParser", "MSParser"]

class StatResult(tuple[Any, ...]):
    def __init__(self, sequence: Any) -> None: ...
    def __getattr__(self, attr_name: str) -> Any: ...

class Parser:
    def ignores_line(self, line: str) -> bool: ...
    def parse_line(self, line: str, time_shift: float = 0.0) -> StatResult: ...
    def parse_unix_mode(self, mode_string: str) -> int: ...
    def parse_unix_time(
        self,
        month_abbreviation: str,
        day: str,
        year_or_time: str,
        time_shift: float,
        with_precision: bool = False,
    ) -> float: ...
    def parse_ms_time(
        self, date: str, time_: str, time_shift: float, with_precision: bool = False
    ) -> float: ...

class UnixParser(Parser):
    def parse_line(self, line: str, time_shift: float = 0.0) -> StatResult: ...

class MSParser(Parser):
    def parse_line(self, line: str, time_shift: float = 0.0) -> StatResult: ...

class _Stat:
    def __init__(self, host: FTPHost) -> None: ...
