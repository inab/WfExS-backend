from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
)
from gzip import GzipFile, _GzipReader
from io import FileIO
from typing import (
    Any,
    IO,
    Iterable,
    MutableSequence,
    Optional,
    Sequence,
    Tuple,
)
from typing_extensions import (
    Buffer,
    Literal,
)
import zlib

SID: bytes

def open(
    filename: str,
    mode: str = ...,
    compresslevel: int = ...,
    encoding: Optional[str] = ...,
    errors: Optional[str] = ...,
    newline: Optional[str] = ...,
    thread: Optional[int] = ...,
    blocksize: int = ...,
) -> IO[bytes]: ...
def compress(
    data: bytes,
    compresslevel: int = ...,
    thread: Optional[int] = ...,
    blocksize: int = ...,
) -> bytes: ...
def decompress(
    data: bytes, thread: Optional[int] = ..., blocksize: int = ...
) -> bytes: ...
def padded_file_seek(self: PgzipFile, off: int, whence: int = ...) -> int: ...

class PgzipFile(GzipFile):
    thread: int
    read_blocks: Optional[Any]
    mode: Literal[1, 2]
    raw: _MulitGzipReader
    name: str
    index: MutableSequence[MutableSequence[int]]
    compress: zlib._Compress
    compresslevel: int
    blocksize: int
    pool: ThreadPoolExecutor
    pool_result: MutableSequence[Future[Tuple[bytes, bytes, bytes, int, int]]]
    small_buf: IO[bytes]
    fileobj: IO[bytes]
    def __init__(
        self,
        filename: Optional[str] = ...,
        mode: Optional[str] = ...,
        compresslevel: int = ...,
        fileobj: Optional[IO[bytes]] = ...,
        mtime: Optional[float] = ...,
        thread: Optional[int] = ...,
        blocksize: int = ...,
    ) -> None: ...
    def write(self, data: Buffer) -> int: ...
    def get_index(self) -> MutableSequence[MutableSequence[int]]: ...
    def show_index(self) -> None: ...
    def build_index(
        self, idx_file: Optional[str] = ...
    ) -> MutableSequence[MutableSequence[int]]: ...
    def load_index(self, idx_file: str) -> MutableSequence[MutableSequence[int]]: ...
    def set_read_blocks(self, block_ids: Sequence[int]) -> None: ...
    def set_read_blocks_by_name(self, block_names: Sequence[str]) -> None: ...
    def clear_read_blocks(self) -> None: ...
    myfileobj: FileIO
    def close(self) -> None: ...
    def flush(self, zlib_mode: int = ...) -> None: ...

class _MulitGzipReader(_GzipReader):
    memberidx: MutableSequence[Tuple[int, int]]
    max_block_size: int
    thread: int
    block_start_iter: Optional[Iterable[int]]
    def __init__(
        self, fp: Any, thread: int = ..., max_block_size: int = ...
    ) -> None: ...
    def read(self, size: int = ...) -> bytes: ...
    def set_block_iter(self, block_start_list: Sequence[int]) -> None: ...
    def clear_block_iter(self) -> None: ...
