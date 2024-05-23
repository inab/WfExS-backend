from _typeshed import Incomplete
from _typeshed import SupportsRead
from xml.sax import ErrorHandler as _ErrorHandler
from xml.sax.handler import ContentHandler as _ContentHandler
from .expatreader import DefusedExpatParser

__origin__: str

def parse(
    source: str | SupportsRead[bytes | str],
    handler: _ContentHandler,
    errorHandler: _ErrorHandler = ...,
    forbid_dtd: bool = False,
    forbid_entities: bool = True,
    forbid_external: bool = True,
) -> None: ...
def parseString(
    string: str,
    handler: _ContentHandler,
    errorHandler: _ErrorHandler = ...,
    forbid_dtd: bool = False,
    forbid_entities: bool = True,
    forbid_external: bool = True,
) -> None: ...
def make_parser(parser_list: list[Incomplete] = []) -> DefusedExpatParser: ...
