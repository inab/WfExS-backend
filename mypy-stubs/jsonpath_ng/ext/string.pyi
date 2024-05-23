from typing import (
    Any,
    Optional,
    Pattern,
    Sequence,
)
from .. import DatumInContext as DatumInContext, This as This
from ..jsonpath import JSONVal

SUB: Pattern[str]
SPLIT: Pattern[str]
STR: Pattern[str]

class DefintionInvalid(Exception): ...

class Sub(This):
    expr: str
    repl: str
    regex: Pattern[str]
    method: Optional[str]
    def __init__(self, method: Optional[str] = ...) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...

class Split(This):
    char: str
    segment: int
    max_split: int
    method: Optional[str]
    def __init__(self, method: Optional[str] = ...) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...

class Str(This):
    method: Optional[str]
    def __init__(self, method: Optional[str] = ...) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...
