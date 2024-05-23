from _typeshed import Incomplete
from xmlrpc.client import (
    ExpatParser,
    Unmarshaller,
)

__origin__: str
MAX_DATA: int = 31457280

def defused_gzip_decode(data: bytes | bytearray, limit: int | None = None) -> bytes: ...

# Couldn't type this as a class deriving from gzip.GzipFile
# since overwriting `read` method does not define an optional argument
# for size when the underlying class does.
DefusedGzipDecodedResponse = Incomplete

class DefusedExpatParser(ExpatParser):
    forbid_dtd: bool
    forbid_entities: bool
    forbid_external: bool
    def __init__(
        self,
        target: Unmarshaller,
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

def monkey_patch() -> None: ...
def unmonkey_patch() -> None: ...
