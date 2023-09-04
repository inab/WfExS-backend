from typing import (
    Pattern,
)

DATA_URL_RE: Pattern[str]

def construct_data_url(
    mime_type: str, base64_encode: bool, data: str | bytes
) -> str: ...

class DataURL:
    URL_FORMAT: str
    ENCODING_STRING: str
    @classmethod
    def from_url(cls, url: str) -> DataURL: ...
    @classmethod
    def from_data(
        cls, mime_type: str, base64_encode: bool, data: str | bytes
    ) -> DataURL: ...
    @property
    def url(self) -> str: ...
    @property
    def is_base64_encoded(self) -> bool: ...
    @property
    def mime_type(self) -> str: ...
    @property
    def data(self) -> bytes: ...
    @property
    def encoded_data(self) -> str | bytes: ...
