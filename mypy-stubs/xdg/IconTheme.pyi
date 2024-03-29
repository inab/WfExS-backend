from typing import (
    Any,
    MutableMapping,
    MutableSequence,
    Optional,
    Sequence,
    Tuple,
)

from xdg.BaseDirectory import xdg_data_dirs as xdg_data_dirs
from xdg.Exceptions import NoThemeError as NoThemeError, debug as debug
from xdg.IniFile import IniFile as IniFile, is_ascii as is_ascii

class IconTheme(IniFile):
    def __init__(self) -> None: ...
    dir: str
    def parse(self, file: str) -> None: ...
    def getDir(self) -> str: ...
    def getName(self) -> str: ...
    def getComment(self) -> str: ...
    def getInherits(self) -> Sequence[str]: ...
    def getDirectories(self) -> Sequence[str]: ...
    def getScaledDirectories(self) -> Sequence[str]: ...
    def getHidden(self) -> bool: ...
    def getExample(self) -> str: ...
    def getSize(self, directory: str) -> int: ...
    def getContext(self, directory: str) -> str: ...
    def getType(self, directory: str) -> str: ...
    def getMaxSize(self, directory: str) -> int: ...
    def getMinSize(self, directory: str) -> int: ...
    def getThreshold(self, directory: str) -> int: ...
    def getScale(self, directory: str) -> int: ...
    name: str
    comment: str
    directories: str
    def checkExtras(self) -> None: ...
    type: str
    def checkGroup(self, group: str) -> None: ...
    def checkKey(self, key: str, value: str, group: str) -> None: ...

class IconData(IniFile):
    def __init__(self) -> None: ...
    def parse(self, file: str) -> None: ...
    def getDisplayName(self) -> str: ...
    def getEmbeddedTextRectangle(self) -> Sequence[int]: ...
    def getAttachPoints(self) -> Sequence[Tuple[int, int]]: ...
    def checkExtras(self) -> None: ...
    def checkGroup(self, group: str) -> None: ...
    def checkKey(self, key: str, value: str, group: str) -> None: ...

icondirs: MutableSequence[str]
themes: MutableSequence[IconTheme]
theme_cache: MutableMapping[str, Sequence[Any]]
dir_cache: MutableMapping[str, Tuple[Sequence[str], float, float]]
icon_cache: MutableMapping[Tuple[str, int, str, Tuple[str, ...]], Tuple[float, str]]

def getIconPath(
    iconname: str,
    size: Optional[int] = ...,
    theme: Optional[str] = ...,
    extensions: Sequence[str] = ...,
) -> str: ...
def getIconData(path: str) -> Optional[IconData]: ...
def LookupIcon(
    iconname: str, size: int, theme: str, extensions: Sequence[str]
) -> str: ...
def DirectoryMatchesSize(
    subdir: str, iconsize: int, theme: IconTheme
) -> Optional[bool]: ...
def DirectorySizeDistance(subdir: str, iconsize: int, theme: IconTheme) -> int: ...
