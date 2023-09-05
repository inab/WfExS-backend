from .pgzip import (
    PgzipFile,
    compress as compress,
    decompress as decompress,
    open as open,
)

GzipFile = PgzipFile
