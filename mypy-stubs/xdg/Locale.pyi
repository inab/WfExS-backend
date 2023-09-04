from typing import (
    Optional,
    Sequence,
)

regex: str

def expand_languages(languages: Optional[Sequence[str]] = ...) -> Sequence[str]: ...
def update(language: Optional[str] = ...) -> None: ...

langs: Sequence[str]
