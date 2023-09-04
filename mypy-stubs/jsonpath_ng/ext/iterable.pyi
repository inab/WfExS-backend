from typing import (
    Any,
    Sequence,
)

from .. import DatumInContext as DatumInContext, JSONPath as JSONPath, This as This
from ..jsonpath import JSONVal

class SortedThis(This):
    expressions: Optional[Sequence[Any]]
    def __init__(self, expressions: Optional[Sequence[Any]] = ...) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...

class Len(JSONPath):
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...
