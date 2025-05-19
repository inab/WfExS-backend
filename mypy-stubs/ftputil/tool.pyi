from typing import (
    Any,
)

__all__ = ["same_string_type_as", "as_str", "as_str_path", "raise_for_empty_path"]

def same_string_type_as(
    type_source: bytes | str, string: bytes | str, encoding: str
) -> bytes | str: ...
def as_str(string: bytes | str, encoding: str) -> str: ...
def as_str_path(path: bytes | str, encoding: str) -> str: ...
def raise_for_empty_path(
    path: bytes | str, path_argument_name: str = "path"
) -> None: ...
