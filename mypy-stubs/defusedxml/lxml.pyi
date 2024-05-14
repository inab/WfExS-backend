import threading
from _typeshed import Incomplete
from _typeshed import SupportsRead
from typing import (
    Iterator,
    Sequence,
)

# Not bothering with types here as lxml support is supposed to be dropped in a future version
# of defusedxml

LXML3: Incomplete
__origin__: str
tostring: Incomplete

# Should be imported from lxml.etree.ElementBase, but lxml lacks types
class _ElementBase: ...

class RestrictedElement(_ElementBase):
    blacklist: Incomplete
    def __iter__(self) -> Iterator[_ElementBase]: ...
    def iterchildren(
        self, tag: Incomplete | None = ..., reversed: bool = ...
    ) -> Iterator[_ElementBase]: ...
    def iter(
        self, tag: _ElementBase | None = ..., *tags: _ElementBase
    ) -> Iterator[_ElementBase]: ...
    def iterdescendants(
        self, tag: _ElementBase | None = ..., *tags: _ElementBase
    ) -> Iterator[_ElementBase]: ...
    def itersiblings(
        self, tag: Incomplete | None = ..., preceding: bool = ...
    ) -> Iterator[_ElementBase]: ...
    def getchildren(self) -> Sequence[_ElementBase]: ...
    def getiterator(self, tag: Incomplete | None = ...) -> Iterator[_ElementBase]: ...

class GlobalParserTLS(threading.local):
    parser_config: Incomplete
    element_class: Incomplete
    def createDefaultParser(self) -> Incomplete: ...
    def setDefaultParser(self, parser: Incomplete) -> None: ...
    def getDefaultParser(self) -> Incomplete: ...

getDefaultParser: Incomplete

def check_docinfo(
    elementtree: Incomplete, forbid_dtd: bool = ..., forbid_entities: bool = ...
) -> None: ...
def parse(
    source: str | SupportsRead[bytes | str],
    parser: Incomplete | None = ...,
    base_url: Incomplete | None = ...,
    forbid_dtd: bool = ...,
    forbid_entities: bool = ...,
) -> Incomplete: ...
def fromstring(
    text: str,
    parser: Incomplete | None = ...,
    base_url: Incomplete | None = ...,
    forbid_dtd: bool = ...,
    forbid_entities: bool = ...,
) -> Incomplete: ...

XML = fromstring

def iterparse(*args: str, **kwargs: str) -> None: ...
