from collections.abc import Iterator, Sequence
from typing import Any
from _typeshed import SupportsRead
from xml.etree.ElementTree import Element, ElementTree, ParseError as ParseError, TreeBuilder as _TreeBuilder, XMLParser as _XMLParser, tostring as tostring

class DefusedXMLParser(_XMLParser):
    forbid_dtd: bool
    forbid_entities: bool
    forbid_external: bool
    def __init__(
        self,
        html: object | bool =...,
        target: _TreeBuilder | None = None,
        encoding: str | None = None,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> None: ...
    def defused_start_doctype_decl(self, name: str | None, sysid: str | None, pubid: str | None, has_internal_subset: bool) -> None: ...
    def defused_entity_decl(self, name: str | None, is_parameter_entity: bool, value: str | None, base: str | None, sysid: str | None, pubid: str | None, notation_name: str | None) -> None: ...
    def defused_unparsed_entity_decl(self, name: str | None, base: str | None, sysid: str | None, pubid: str | None, notation_name: str | None) -> None: ...
    def defused_external_entity_ref_handler(self, context: str | None, base: str | None, sysid: str | None, pubid: str | None) -> None: ...

XMLTreeBuilder = DefusedXMLParser
XMLParse = DefusedXMLParser
XMLParser = DefusedXMLParser

# wrapper to xml.etree.ElementTree.parse
def parse(
    source: str | SupportsRead[bytes] | SupportsRead[str], parser: _XMLParser | None = None, forbid_dtd: bool = False, forbid_entities: bool = True, forbid_external: bool = True
) -> ElementTree: ...

# wrapper to xml.etree.ElementTree.iterparse
def iterparse(
    source: str | SupportsRead[bytes] | SupportsRead[str],
    events: Sequence[str] | None = None,
    parser: _XMLParser | None = None,
    forbid_dtd: bool = False,
    forbid_entities: bool = True,
    forbid_external: bool = True,
) -> Iterator[tuple[str, Any]]: ...
def fromstring(text: str, forbid_dtd: bool = False, forbid_entities: bool = True, forbid_external: bool = True) -> Element: ...

XML = fromstring

__all__ = ["ParseError", "XML", "XMLParse", "XMLParser", "XMLTreeBuilder", "fromstring", "iterparse", "parse", "tostring"]
