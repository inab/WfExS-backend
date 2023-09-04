from typing import (
    Sequence,
)

from .. import DatumInContext as DatumInContext, JSONPath as JSONPath
from ..jsonpath import JSONVal

OPERATOR_MAP: Mapping[str, Callable[[float, float], float]]

class Operation(JSONPath):
    left: JSONPath
    op: Callable[[float, float], float]
    right: JSONPath
    def __init__(
        self, left: JSONPath | JSONVal, op: str, right: JSONPath | JSONVal
    ) -> None: ...
    def find(self, datum: DatumInContext | JSONVal) -> Sequence[DatumInContext]: ...
