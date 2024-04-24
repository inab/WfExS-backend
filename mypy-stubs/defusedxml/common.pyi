PY3: bool

class DefusedXmlException(ValueError): ...

class DTDForbidden(DefusedXmlException):
    name: str | None
    sysid: str | None
    pubid: str | None
    def __init__(
        self, name: str | None, sysid: str | None, pubid: str | None
    ) -> None: ...

class EntitiesForbidden(DefusedXmlException):
    name: str | None
    value: str | None
    base: str | None
    sysid: str | None
    pubid: str | None
    notation_name: str | None
    def __init__(
        self,
        name: str | None,
        value: str | None,
        base: str | None,
        sysid: str | None,
        pubid: str | None,
        notation_name: str | None,
    ) -> None: ...

class ExternalReferenceForbidden(DefusedXmlException):
    context: str | None
    base: str | None
    sysid: str | None
    pubid: str | None
    def __init__(
        self,
        context: str | None,
        base: str | None,
        sysid: str | None,
        pubid: str | None,
    ) -> None: ...

class NotSupportedError(DefusedXmlException): ...
