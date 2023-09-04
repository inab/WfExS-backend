from typing import (
    Any,
    Sequence,
)
from .. import DatumInContext as DatumInContext, Index as Index, JSONPath as JSONPath
from ..jsonpath import JSONVal
from _typeshed import Incomplete

OPERATOR_MAP: Mapping[str, Callable[[Any, Any], bool]]

class Filter(JSONPath):
    expressions: Sequence[JSONPath]
    def __init__(self, expressions: Sequence[JSONPath]) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def update(self, data: JSONVal, val: JSONVal) -> JSONVal: ...
    def __eq__(self, other: Any) -> bool: ...

class Expression(JSONPath):
    target: Any
    op: Callable[[Any, Any], bool]
    value: Any
    def __init__(self, target: Any, op: str, value: Any) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
    def __eq__(self, other: Any) -> bool: ...
