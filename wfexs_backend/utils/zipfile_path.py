#!/usr/bin/env python
# -*- coding: utf-8 -*-

# These fragments of code are borrowed from Python 3.10.14 distribution,
# from Lib/zipfile.py , in order to backport zipfile.Path to Python 3.7
# Method body from path_relative_to is borrowed from Python 3.12
# zipfile.Path.relative_to method.

# SPDX-License-Identifier: PSF-2.0
# Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022,
# 2023 Python Software Foundation; All Rights Reserved

import contextlib
import functools
import inspect
import io
import itertools
import logging
import os
import pathlib
import posixpath
import shutil
import sys

from typing import (
    cast,
    TYPE_CHECKING,
)

import zipfile


if TYPE_CHECKING:
    import os

    from typing import (
        Any,
        Dict,
        Generator,
        IO,
        Iterable,
        Iterator,
        List,
        Mapping,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Literal,
    )


def _parents(path: "str") -> "Iterator[str]":
    """
    Given a path with elements separated by
    posixpath.sep, generate all parents of that path.

    >>> list(_parents('b/d'))
    ['b']
    >>> list(_parents('/b/d/'))
    ['/b']
    >>> list(_parents('b/d/f/'))
    ['b/d', 'b']
    >>> list(_parents('b'))
    []
    >>> list(_parents(''))
    []
    """
    return itertools.islice(_ancestry(path), 1, None)


def _ancestry(path: "str") -> "Iterator[str]":
    """
    Given a path with elements separated by
    posixpath.sep, generate all elements of that path

    >>> list(_ancestry('b/d'))
    ['b/d', 'b']
    >>> list(_ancestry('/b/d/'))
    ['/b/d', '/b']
    >>> list(_ancestry('b/d/f/'))
    ['b/d/f', 'b/d', 'b']
    >>> list(_ancestry('b'))
    ['b']
    >>> list(_ancestry(''))
    []
    """
    path = path.rstrip(posixpath.sep)
    while path and path != posixpath.sep:
        yield path
        path, tail = posixpath.split(path)


_dedupe = dict.fromkeys
"""Deduplicate an iterable in original order"""


def _difference(
    minuend: "Iterable[str]", subtrahend: "Iterable[str]"
) -> "Iterator[str]":
    """
    Return items in minuend not in subtrahend, retaining order
    with O(1) lookup.
    """
    return itertools.filterfalse(set(subtrahend).__contains__, minuend)


class CompleteDirs(zipfile.ZipFile):
    """
    A ZipFile subclass that ensures that implied directories
    are always included in the namelist.
    """

    @staticmethod
    def _implied_dirs(names: "Sequence[str]") -> "Mapping[str, Optional[str]]":
        parents = itertools.chain.from_iterable(map(_parents, names))
        as_dirs = (p + posixpath.sep for p in parents)
        return _dedupe(_difference(as_dirs, names))

    def namelist(self) -> "List[str]":
        names = super(CompleteDirs, self).namelist()
        return names + list(self._implied_dirs(names))

    def _name_set(self) -> "Set[str]":
        return set(self.namelist())

    def resolve_dir(self, name: "str") -> "str":
        """
        If the name represents a directory, return that name
        as a directory (with the trailing slash).
        """
        names = self._name_set()
        dirname = name + "/"
        dir_match = name not in names and dirname in names
        return dirname if dir_match else name

    def getinfo(self, name: "str") -> "zipfile.ZipInfo":
        """
        Supplement getinfo for implied dirs.
        """
        try:
            return super().getinfo(name)
        except KeyError:
            if not name.endswith("/") or name not in self._name_set():
                raise
            return zipfile.ZipInfo(filename=name)

    @classmethod
    def make(
        cls, source: "Union[CompleteDirs, zipfile.ZipFile, str, os.PathLike[str]]"
    ) -> "CompleteDirs":
        """
        Given a source (filename or zipfile), return an
        appropriate CompleteDirs subclass.
        """
        if isinstance(source, CompleteDirs):
            return source

        if not isinstance(source, zipfile.ZipFile):
            return cls(source)

        # Only allow for FastPath when supplied zipfile is read-only
        if "r" not in source.mode:
            cls = CompleteDirs

        res = cls.__new__(cls)
        return res


class FastLookup(CompleteDirs):
    """
    ZipFile subclass to ensure implicit
    dirs exist and are resolved rapidly.
    """

    def namelist(self) -> "List[str]":
        self.__names: "List[str]"
        with contextlib.suppress(AttributeError):
            return self.__names  # pylint: disable=access-member-before-definition
        self.__names = super(FastLookup, self).namelist()
        return self.__names

    def _name_set(self) -> "Set[str]":
        self.__lookup: "Set[str]"
        with contextlib.suppress(AttributeError):
            return self.__lookup  # pylint: disable=access-member-before-definition
        self.__lookup = super(FastLookup, self)._name_set()
        return self.__lookup


def path_relative_to(
    path: "pathlib.Path", other: "pathlib.Path", *extra: "Union[str, os.PathLike[str]]"
) -> "str":
    # Method body is partially borrowed from Python 3.12
    # zipfile.Path.relative_to method.
    return posixpath.relpath(str(path), str(other.joinpath(*extra)))


# Older versions of Python do not have zipfile.Path
# and newer are not compatible with pathlib.Path
class ZipfilePath(pathlib.Path):
    """
    A pathlib-compatible interface for zip files.

    Consider a zip file with this structure::

        .
        ├── a.txt
        └── b
            ├── c.txt
            └── d
                └── e.txt

    >>> data = io.BytesIO()
    >>> zf = zipfile.ZipFile(data, 'w')
    >>> zf.writestr('a.txt', 'content of a')
    >>> zf.writestr('b/c.txt', 'content of c')
    >>> zf.writestr('b/d/e.txt', 'content of e')
    >>> zf.filename = 'mem/abcde.zip'

    Path accepts the zipfile object itself or a filename

    >>> root = Path(zf)

    From there, several path operations are available.

    Directory iteration (including the zip file itself):

    >>> a, b = root.iterdir()
    >>> a
    Path('mem/abcde.zip', 'a.txt')
    >>> b
    Path('mem/abcde.zip', 'b/')

    name property:

    >>> b.name
    'b'

    join with divide operator:

    >>> c = b / 'c.txt'
    >>> c
    Path('mem/abcde.zip', 'b/c.txt')
    >>> c.name
    'c.txt'

    Read text:

    >>> c.read_text()
    'content of c'

    existence:

    >>> c.exists()
    True
    >>> (b / 'missing.txt').exists()
    False

    Coercion to string:

    >>> import os
    >>> str(c).replace(os.sep, posixpath.sep)
    'mem/abcde.zip/b/c.txt'

    At the root, ``name``, ``filename``, and ``parent``
    resolve to the zipfile. Note these attributes are not
    valid and will raise a ``ValueError`` if the zipfile
    has no filename.

    >>> root.name
    'abcde.zip'
    >>> str(root.filename).replace(os.sep, posixpath.sep)
    'mem/abcde.zip'
    >>> str(root.parent)
    'mem'
    """

    __repr = "{self.__class__.__name__}({self._root.filename!r}, {self._at!r})"

    def __init__(
        self,
        root: "Union[str, CompleteDirs, os.PathLike[str], zipfile.ZipFile]",
        at: "str" = "",
    ):
        """
        Construct a Path from a ZipFile or filename.

        Note: When the source is an existing ZipFile object,
        its type (__class__) will be mutated to a
        specialized type. If the caller wishes to retain the
        original type, the caller should either create a
        separate ZipFile object or pass a filename.
        """
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self._root = FastLookup.make(root)
        self._at = at

    def open(  # type: ignore[override]
        self,
        mode: "str" = "r",
        pwd: "Optional[bytes]" = None,
        buffering: "int" = -1,
        encoding: "Optional[str]" = None,
        newline: "Optional[str]" = None,
    ) -> "Union[IO[str], IO[bytes]]":
        """
        Open this entry as text or binary following the semantics
        of ``pathlib.Path.open()`` by passing arguments through
        to io.TextIOWrapper().
        """
        if self.is_dir():
            raise IsADirectoryError(self)
        zip_mode = mode[0]
        if not self.exists() and zip_mode == "r":
            raise FileNotFoundError(self)
        stream = self._root.open(
            self._at, mode=cast("Literal['r', 'w']", zip_mode), pwd=pwd
        )
        if "b" in mode:
            # if args or kwargs:
            #    raise ValueError("encoding args invalid for binary operation")
            return stream
        # Text mode:
        return io.TextIOWrapper(
            stream,
            encoding=encoding,
            newline=newline,
            line_buffering=(buffering > 0),
        )

    @property
    def name(self) -> "str":
        return pathlib.Path(self._at).name or self.filename.name

    @property
    def filename(self) -> "pathlib.Path":
        assert self._root.filename is not None
        return pathlib.Path(self._root.filename).joinpath(self._at)

    def read_text(self, *args: "Any", **kwargs: "Any") -> "str":
        kwargs["mode"] = "r"
        with self.open(*args, **kwargs) as strm:
            return cast("str", strm.read())

    def read_bytes(self) -> "bytes":
        with self.open("rb") as strm:
            return cast("bytes", strm.read())

    def _is_child(self, path: "ZipfilePath") -> "bool":
        return posixpath.dirname(path._at.rstrip("/")) == self._at.rstrip("/")

    def _next(self, at: "str") -> "ZipfilePath":
        return self.__class__(self._root, at)

    def is_dir(self) -> "bool":
        return not self._at or self._at.endswith("/")

    def is_file(self) -> "bool":
        return self.exists() and not self.is_dir()

    def exists(self, *, follow_symlinks: bool = False) -> "bool":
        return self._at in self._root._name_set()

    def iterdir(self) -> "Generator[ZipfilePath, None, None]":
        if not self.is_dir():
            raise ValueError("Can't listdir a file")
        subs = map(self._next, self._root.namelist())
        return cast("Generator[ZipfilePath, None, None]", filter(self._is_child, subs))

    def __str__(self) -> "str":
        assert self._root.filename is not None
        return posixpath.join(self._root.filename, self._at)

    def __repr__(self) -> "str":
        return self.__repr.format(self=self)

    def joinpath(self, *other: "Union[str, os.PathLike[str]]") -> "ZipfilePath":
        next = posixpath.join(self._at, *other)
        return self._next(self._root.resolve_dir(next))

    __truediv__ = joinpath

    @property
    def parent(self) -> "ZipfilePath":
        if not self._at:
            return self.filename.parent  # type: ignore[return-value]
        parent_at = posixpath.dirname(self._at.rstrip("/"))
        if parent_at:
            parent_at += "/"
        return self._next(parent_at)

    @property
    def zip_root(self) -> "zipfile.ZipFile":
        return self._root

    def relative_to(  # type: ignore[override]
        self,
        other: "Union[str, os.PathLike[str]]",
        # /,
        *_deprecated: "Union[str, os.PathLike[str]]",
        walk_up: bool = False,
    ) -> "pathlib.Path":
        return pathlib.Path(
            path_relative_to(
                self, other if isinstance(other, pathlib.Path) else pathlib.Path(other)
            )
        )

    def resolve(self, strict: "bool" = False) -> "ZipfilePath":
        # TODO: better solution
        return self.__class__(self._root, self._at)

    def _extract_member(
        self,
        member: "Union[zipfile.ZipInfo, str]",
        targetpath: "Union[str, os.PathLike[str]]",
        pwd: "Optional[bytes]" = None,
    ) -> "str":
        """
        Method partially borrowed from python 3.12
        """
        """Extract the ZipInfo object 'member' to a physical
           file on the path targetpath.
        """
        if not isinstance(member, zipfile.ZipInfo):
            member = self._root.getinfo(member)

        # build the destination pathname, replacing
        # forward slashes to platform specific separators.
        arcname = member.filename.replace("/", os.path.sep)

        if os.path.altsep:
            arcname = arcname.replace(os.path.altsep, os.path.sep)
        # interpret absolute pathname as relative, remove drive letter or
        # UNC path, redundant separators, "." and ".." components.
        arcname = os.path.splitdrive(arcname)[1]
        invalid_path_parts = ("", os.path.curdir, os.path.pardir)
        arcname = os.path.sep.join(
            x for x in arcname.split(os.path.sep) if x not in invalid_path_parts
        )
        # if os.path.sep == "\\":
        #    # filter illegal characters on Windows
        #    arcname = self._root._sanitize_windows_name(arcname, os.path.sep)

        if not arcname and not member.is_dir():
            raise ValueError("Empty filename.")

        targetpath = os.path.normpath(targetpath)

        # Create all upper directories if necessary.
        upperdirs = os.path.dirname(targetpath)
        if upperdirs and not os.path.exists(upperdirs):
            os.makedirs(upperdirs)

        if member.is_dir():
            if not os.path.isdir(targetpath):
                os.mkdir(targetpath)
            return targetpath

        with self._root.open(member, pwd=pwd) as source, open(
            targetpath, "wb"
        ) as target:
            shutil.copyfileobj(source, target)

        return targetpath

    def copy_to(self, dest: "pathlib.Path") -> "None":
        if self.is_file():
            self._extract_member(self._at, dest)
        else:
            the_members: "Sequence[str]"
            if self._at != "":
                the_members = list(
                    filter(
                        lambda name: name.startswith(self._at), self._root.namelist()
                    )
                )
            else:
                the_members = self._root.namelist()
            for the_member in the_members:
                the_partial_member = the_member[len(self._at) :]
                self._extract_member(the_member, dest / the_partial_member)

    def with_name(self, name: "Union[str, os.PathLike[str]]") -> "ZipfilePath":
        return self.parent.joinpath(name)
