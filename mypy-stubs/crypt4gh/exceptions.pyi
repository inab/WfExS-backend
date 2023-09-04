from logging import Logger
from typing import (
    Any,
    Callable,
)

LOG: Logger

from typing_extensions import (
    Protocol,
)

class WrappableFunc(Protocol):
    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...

def convert_error(func: WrappableFunc) -> WrappableFunc: ...
def close_on_broken_pipe(func: WrappableFunc) -> WrappableFunc: ...
def exit_on_invalid_passphrase(func: WrappableFunc) -> WrappableFunc: ...
