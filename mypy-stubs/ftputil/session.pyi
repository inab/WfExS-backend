import ftplib
from typing import (
    Type,
)

__all__ = ["session_factory"]

def session_factory(
    base_class: Type[ftplib.FTP] = ...,
    port: int = 21,
    use_passive_mode: bool | None = None,
    *,
    encrypt_data_channel: bool = True,
    encoding: str | None = None,
    debug_level: int | None = None
) -> Type[ftplib.FTP]: ...
