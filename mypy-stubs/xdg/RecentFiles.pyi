from typing import (
    MutableSequence,
    Optional,
    Sequence,
)

from xdg.Exceptions import ParsingError as ParsingError

class RecentFiles:
    RecentFiles: MutableSequence[RecentFile]
    filename: str
    def __init__(self) -> None: ...
    def parse(self, filename: Optional[str] = ...) -> None: ...
    def write(self, filename: Optional[str] = ...) -> None: ...
    def getFiles(
        self,
        mimetypes: Optional[Sequence[str]] = ...,
        groups: Optional[Sequence[str]] = ...,
        limit: int = ...,
    ): ...
    def addFile(
        self,
        item: RecentFile,
        mimetype: str,
        groups: Optional[Sequence[str]] = ...,
        private: bool = ...,
    ) -> None: ...
    def deleteFile(self, item: RecentFile) -> None: ...
    def sort(self) -> None: ...

class RecentFile:
    URI: str
    MimeType: str
    Timestamp: str
    Private: bool
    Groups: MutableSequence[str]
    def __init__(self) -> None: ...
    def __cmp__(self, other: RecentFile): ...
    def __lt__(self, other: RecentFile): ...
    def __eq__(self, other: RecentFile): ...
