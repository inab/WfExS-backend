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
import io
import itertools
import pathlib
import posixpath
from typing import (
    cast,
    TYPE_CHECKING,
)
from zipfile import (
    ZipFile,
    ZipInfo,
)


if TYPE_CHECKING:
    from os import (
        PathLike,
    )

    from typing import (
        Any,
        Dict,
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


class CompleteDirs(ZipFile):
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

    def getinfo(self, name: "str") -> "ZipInfo":
        """
        Supplement getinfo for implied dirs.
        """
        try:
            return super().getinfo(name)
        except KeyError:
            if not name.endswith("/") or name not in self._name_set():
                raise
            return ZipInfo(filename=name)

    @classmethod
    def make(
        cls, source: "Union[CompleteDirs, ZipFile, str, PathLike[str]]"
    ) -> "CompleteDirs":
        """
        Given a source (filename or zipfile), return an
        appropriate CompleteDirs subclass.
        """
        if isinstance(source, CompleteDirs):
            return source

        if not isinstance(source, ZipFile):
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


def _extract_text_encoding(
    encoding: "Optional[str]" = None, *args: "Any", **kwargs: "Any"
) -> "Tuple[str, Tuple[Any], Dict[str, Any]]":
    # stacklevel=3 so that the caller of the caller see any warning.
    return io.text_encoding(encoding, 3), args, kwargs


def path_relative_to(
    path: "Union[Path, pathlib.Path]",
    other: "Union[Path, pathlib.Path]",
    *extra: "Union[str, PathLike[str]]"
) -> "str":
    # Method body is borrowed from Python 3.12
    # zipfile.Path.relative_to method.
    return posixpath.relpath(str(path), str(other.joinpath(*extra)))


class Path:
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
    >>> zf = ZipFile(data, 'w')
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

    __repr = "{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"

    def __init__(
        self, root: "Union[str, CompleteDirs, PathLike[str], ZipFile]", at: "str" = ""
    ):
        """
        Construct a Path from a ZipFile or filename.

        Note: When the source is an existing ZipFile object,
        its type (__class__) will be mutated to a
        specialized type. If the caller wishes to retain the
        original type, the caller should either create a
        separate ZipFile object or pass a filename.
        """
        self.root = FastLookup.make(root)
        self.at = at

    def open(
        self,
        mode: "str" = "r",
        *args: "Any",
        pwd: "Optional[bytes]" = None,
        **kwargs: "Any"
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
        stream = self.root.open(self.at, zip_mode, pwd=pwd)
        if "b" in mode:
            if args or kwargs:
                raise ValueError("encoding args invalid for binary operation")
            return stream
        # Text mode:
        encoding, args, kwargs = _extract_text_encoding(*args, **kwargs)
        return io.TextIOWrapper(stream, encoding, *args, **kwargs)

    @property
    def name(self) -> "str":
        return pathlib.Path(self.at).name or self.filename.name

    @property
    def filename(self) -> "pathlib.Path":
        assert self.root.filename is not None
        return pathlib.Path(self.root.filename).joinpath(self.at)

    def read_text(self, *args: "Any", **kwargs: "Any") -> "str":
        encoding, args, kwargs = _extract_text_encoding(*args, **kwargs)
        with self.open("r", encoding, *args, **kwargs) as strm:
            return cast("str", strm.read())

    def read_bytes(self) -> "bytes":
        with self.open("rb") as strm:
            return cast("bytes", strm.read())

    def _is_child(self, path: "Path") -> "bool":
        return posixpath.dirname(path.at.rstrip("/")) == self.at.rstrip("/")

    def _next(self, at: "str") -> "Path":
        return self.__class__(self.root, at)

    def is_dir(self) -> "bool":
        return not self.at or self.at.endswith("/")

    def is_file(self) -> "bool":
        return self.exists() and not self.is_dir()

    def exists(self) -> "bool":
        return self.at in self.root._name_set()

    def iterdir(self) -> "Iterator[Path]":
        if not self.is_dir():
            raise ValueError("Can't listdir a file")
        subs = map(self._next, self.root.namelist())
        return filter(self._is_child, subs)

    def __str__(self) -> "str":
        assert self.root.filename is not None
        return posixpath.join(self.root.filename, self.at)

    def __repr__(self) -> "str":
        return self.__repr.format(self=self)

    def joinpath(self, *other: "Union[str, PathLike[str]]") -> "Path":
        next = posixpath.join(self.at, *other)
        return self._next(self.root.resolve_dir(next))

    __truediv__ = joinpath

    @property
    def parent(self) -> "Union[Path, pathlib.Path]":
        if not self.at:
            return self.filename.parent
        parent_at = posixpath.dirname(self.at.rstrip("/"))
        if parent_at:
            parent_at += "/"
        return self._next(parent_at)
