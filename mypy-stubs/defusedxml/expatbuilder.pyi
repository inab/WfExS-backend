from _typeshed import SupportsRead
from xml.dom.expatbuilder import (
    ExpatBuilder as _ExpatBuilder,
    Namespaces as _Namespaces,
)
from xml.dom.minidom import Document
from xml.dom.xmlbuilder import Options

__origin__: str

class DefusedExpatBuilder(_ExpatBuilder):
    forbid_dtd: bool
    forbid_entities: bool
    forbid_external: bool
    def __init__(
        self,
        options: Options | None = None,
        forbid_dtd: bool = False,
        forbid_entities: bool = True,
        forbid_external: bool = True,
    ) -> None: ...
    def defused_start_doctype_decl(
        self,
        name: str | None,
        sysid: str | None,
        pubid: str | None,
        has_internal_subset: bool,
    ) -> None: ...
    def defused_entity_decl(
        self,
        name: str | None,
        is_parameter_entity: bool,
        value: str | None,
        base: str | None,
        sysid: str | None,
        pubid: str | None,
        notation_name: str | None,
    ) -> None: ...
    def defused_unparsed_entity_decl(
        self,
        name: str | None,
        base: str | None,
        sysid: str | None,
        pubid: str | None,
        notation_name: str | None,
    ) -> None: ...
    def defused_external_entity_ref_handler(
        self,
        context: str | None,
        base: str | None,
        sysid: str | None,
        pubid: str | None,
    ) -> None: ...
    def install(self, parser: _ExpatBuilder) -> None: ...

class DefusedExpatBuilderNS(_Namespaces, DefusedExpatBuilder):
    def install(self, parser: _ExpatBuilder) -> None: ...
    def reset(self) -> None: ...

def parse(
    file: str | SupportsRead[bytes | str],
    namespaces: bool = True,
    forbid_dtd: bool = False,
    forbid_entities: bool = True,
    forbid_external: bool = True,
) -> Document: ...
def parseString(
    string: str,
    namespaces: bool = True,
    forbid_dtd: bool = False,
    forbid_entities: bool = True,
    forbid_external: bool = True,
) -> Document: ...
