from typing import (
    Optional,
    MutableSequence,
)
from xml.etree.ElementTree import Element

from xdg.BaseDirectory import (
    xdg_config_dirs as xdg_config_dirs,
    xdg_data_dirs as xdg_data_dirs,
)
from xdg.Config import setRootMode as setRootMode
from xdg.Exceptions import ParsingError as ParsingError
from xdg.Menu import (
    Layout as Layout,
    Menu as Menu,
    MenuEntry as MenuEntry,
    Separator as Separator,
    XMLMenuBuilder as XMLMenuBuilder,
)

class MenuEditor:
    menu: Optional[Menu]
    filename: Optional[str]
    tree: Optional[Element]
    parser: XMLMenuBuilder
    filenames: MutableSequence[str]
    def __init__(
        self,
        menu: Optional[Menu] = ...,
        filename: Optional[str] = ...,
        root: bool = ...,
    ) -> None: ...
    def parse(
        self,
        menu: Optional[Menu | str] = ...,
        filename: Optional[str] = ...,
        root: bool = ...,
    ) -> None: ...
    def save(self) -> None: ...
    def createMenuEntry(
        self,
        parent: Menu,
        name: str,
        command: Optional[str] = ...,
        genericname: Optional[str] = ...,
        comment: Optional[str] = ...,
        icon: Optional[str] = ...,
        terminal: Optional[bool] = ...,
        after: Optional[MenuEntry] = ...,
        before: Optional[MenuEntry] = ...,
    ) -> MenuEntry: ...
    def createMenu(
        self,
        parent: Menu,
        name,
        genericname: Optional[str] = ...,
        comment: Optional[str] = ...,
        icon: Optional[str] = ...,
        after: Optional[Menu] = ...,
        before: Optional[Menu] = ...,
    ) -> Menu: ...
    def createSeparator(
        self,
        parent: Menu,
        after: Optional[MenuEntry] = ...,
        before: Optional[MenuEntry] = ...,
    ) -> Separator: ...
    def moveMenuEntry(
        self,
        menuentry: MenuEntry,
        oldparent: Menu,
        newparent: Menu,
        after: Optional[MenuEntry] = ...,
        before: Optional[MenuEntry] = ...,
    ) -> MenuEntry: ...
    def moveMenu(
        self,
        menu: Menu,
        oldparent: Menu,
        newparent: Menu,
        after: Optional[Menu] = ...,
        before: Optional[Menu] = ...,
    ) -> Menu: ...
    def moveSeparator(
        self,
        separator: Separator,
        parent: Menu,
        after: Optional[MenuEntry] = ...,
        before: Optional[MenuEntry] = ...,
    ) -> Separator: ...
    def copyMenuEntry(
        self,
        menuentry: MenuEntry,
        oldparent: Menu,
        newparent: Menu,
        after: Optional[MenuEntry] = ...,
        before: Optional[MenuEntry] = ...,
    ) -> MenuEntry: ...
    def editMenuEntry(
        self,
        menuentry: MenuEntry,
        name: Optional[str] = ...,
        genericname: Optional[str] = ...,
        comment: Optional[str] = ...,
        command: Optional[str] = ...,
        icon: Optional[str] = ...,
        terminal: Optional[bool] = ...,
        nodisplay: Optional[bool] = ...,
        hidden: Optional[bool] = ...,
    ) -> MenuEntry: ...
    def editMenu(
        self,
        menu: Menu,
        name: Optional[str] = ...,
        genericname: Optional[str] = ...,
        comment: Optional[str] = ...,
        icon: Optional[str] = ...,
        nodisplay: Optional[bool] = ...,
        hidden: Optional[bool] = ...,
    ) -> Menu: ...
    def hideMenuEntry(self, menuentry: MenuEntry) -> None: ...
    def unhideMenuEntry(self, menuentry: MenuEntry) -> None: ...
    def hideMenu(self, menu: Menu) -> None: ...
    def unhideMenu(self, menu: Menu) -> None: ...
    def deleteMenuEntry(self, menuentry: MenuEntry) -> MenuEntry: ...
    def revertMenuEntry(self, menuentry: MenuEntry) -> MenuEntry: ...
    def deleteMenu(self, menu: Menu) -> Menu: ...
    def revertMenu(self, menu: Menu) -> Menu: ...
    def deleteSeparator(self, separator: Separator) -> Separator: ...
    def getAction(self, entry: Menu | MenuEntry | Separator) -> str: ...
