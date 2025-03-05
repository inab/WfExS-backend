#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import base64
import functools
import hashlib
import json
import os
import stat
from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        IO,
        Iterator,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Protocol,
        TypeAlias,
    )

    from ..common import (
        AbsPath,
        AbstractGeneratedContent,
        AnyPath,
        PathLikePath,
        Fingerprint,
    )

    FingerprintMethod: TypeAlias = Callable[[str, bytes], Fingerprint]
    RawFingerprintMethod: TypeAlias = Callable[[str, bytes], bytes]

    class Hexable(Protocol):
        def hex(self) -> "str":
            ...


from ..common import (
    GeneratedContent,
)

from .misc import (
    DatetimeEncoder,
)

# Next methods have been borrowed from FlowMaps
DEFAULT_DIGEST_ALGORITHM = "sha256"
DEFAULT_DIGEST_BUFFER_SIZE = 65536


def stringifyDigest(digestAlgorithm: "str", digest: "bytes") -> "Fingerprint":
    return cast(
        "Fingerprint",
        "{0}={1}".format(
            digestAlgorithm, str(base64.standard_b64encode(digest), "iso-8859-1")
        ),
    )


def unstringifyDigest(digestion: "Fingerprint") -> "Tuple[bytes, str]":
    if "=" not in digestion:
        raise ValueError(f"The input string {digestion} is not a stringified digest")
    algo, b64digest = digestion.split("=", 1)
    return base64.b64decode(b64digest), algo


def hexDigest(digestAlgorithm: "str", digest: "Hexable") -> "Fingerprint":
    return cast("Fingerprint", digest.hex())


def stringifyFilenameDigest(digestAlgorithm: "str", digest: "bytes") -> "Fingerprint":
    return cast(
        "Fingerprint",
        "{0}~{1}".format(
            digestAlgorithm, str(base64.urlsafe_b64encode(digest), "iso-8859-1")
        ),
    )


def nullProcessDigest(digestAlgorithm: "str", digest: "bytes") -> "bytes":
    return digest


from rfc6920.methods import generate_nih_from_digest

# As of https://datatracker.ietf.org/doc/html/rfc6920#page-17
# rewrite the names of the algorithms
VALID_NI_ALGOS: "Mapping[str, str]" = {
    "sha256": "sha-256",
    "sha256-128": "sha-256-128",
    "sha256_128": "sha-256-128",
    "sha256-120": "sha-256-120",
    "sha256_120": "sha-256-120",
    "sha256-96": "sha-256-96",
    "sha256_96": "sha-256-96",
    "sha256-64": "sha-256-64",
    "sha256_64": "sha-256-64",
    "sha256-32": "sha-256-32",
    "sha256_32": "sha-256-32",
}


def nihDigester(digestAlgorithm: "str", digest: "bytes") -> "Fingerprint":
    # Added fallback, in case it cannot translate the algorithm
    digestAlgorithm = VALID_NI_ALGOS.get(digestAlgorithm, digestAlgorithm)

    return cast("Fingerprint", generate_nih_from_digest(digest, algo=digestAlgorithm))


def ComputeDigestFromObject(
    obj: "Any",
    digestAlgorithm: "str" = DEFAULT_DIGEST_ALGORITHM,
    repMethod: "Union[FingerprintMethod, RawFingerprintMethod]" = stringifyDigest,
) -> "Union[Fingerprint, bytes]":
    """
    Accessory method used to compute the digest of an input file-like object
    """
    h = hashlib.new(digestAlgorithm)
    h.update(json.dumps(obj, cls=DatetimeEncoder, sort_keys=True).encode("utf-8"))

    return repMethod(digestAlgorithm, h.digest())


def ComputeDigestFromFileLike(
    filelike: "IO[bytes]",
    digestAlgorithm: "str" = DEFAULT_DIGEST_ALGORITHM,
    bufferSize: "int" = DEFAULT_DIGEST_BUFFER_SIZE,
    repMethod: "Union[FingerprintMethod, RawFingerprintMethod]" = stringifyDigest,
) -> "Union[Fingerprint, bytes]":
    """
    Accessory method used to compute the digest of an input file-like object
    """
    h = hashlib.new(digestAlgorithm)
    buf = filelike.read(bufferSize)
    while len(buf) > 0:
        h.update(buf)
        buf = filelike.read(bufferSize)

    return repMethod(digestAlgorithm, h.digest())


@functools.lru_cache(maxsize=32)
def ComputeDigestFromFile(
    filename: "PathLikePath",
    digestAlgorithm: "str" = DEFAULT_DIGEST_ALGORITHM,
    bufferSize: "int" = DEFAULT_DIGEST_BUFFER_SIZE,
    repMethod: "Union[FingerprintMethod, RawFingerprintMethod]" = stringifyDigest,
) -> "Optional[Union[Fingerprint, bytes]]":
    """
    Accessory method used to compute the digest of an input file
    """

    # "Fast" compute: no report, no digest
    if repMethod is None:
        return None

    with open(filename, mode="rb") as f:
        return ComputeDigestFromFileLike(f, digestAlgorithm, bufferSize, repMethod)


def compute_sha1_git_from_stream(
    stream: "IO[bytes]", length: "int", buffer_size: "int" = DEFAULT_DIGEST_BUFFER_SIZE
) -> "hashlib._Hash":
    # SHA1 git computes the sha1 by feeding 'blob ' keyword,
    # followed by the ascii representation of the content size in bytes,
    # followed by NUL character and at last the content.
    h = hashlib.sha1()
    h.update(b"blob ")
    h.update(str(length).encode("ascii"))
    h.update(b"\0")

    buf = stream.read(buffer_size)
    got_length = 0
    while len(buf) > 0:
        got_length += len(buf)
        h.update(buf)
        buf = stream.read(buffer_size)

    assert (
        got_length == length
    ), f"Content had size {got_length}, but it was declared to have {length}"

    return h


def compute_sha1_git_from_file(filename: "str") -> "hashlib._Hash":
    length = os.stat(filename).st_size
    with open(filename, mode="rb") as oH:
        return compute_sha1_git_from_stream(oH, length)


def compute_sha1_git_from_bytes(the_bytes: "bytes") -> "hashlib._Hash":
    # SHA1 git computes the sha1 by feeding 'blob ' keyword,
    # followed by the ascii representation of the content size in bytes,
    # followed by NUL character and at last the content.
    h = hashlib.sha1()
    h.update(b"blob ")
    h.update(str(len(the_bytes)).encode("ascii"))
    h.update(b"\0")
    h.update(the_bytes)

    return h


def compute_sha1_git_from_string(the_string: "str") -> "hashlib._Hash":
    return compute_sha1_git_from_bytes(the_string.encode("utf-8"))


def process_dir_entries(
    dirname: "str",
) -> "Iterator[Tuple[bytes, hashlib._Hash, bytes, bool]]":
    for direntry in os.scandir(dirname):
        encoded_dirname = direntry.name.encode("utf-8")
        if direntry.is_symlink():
            yield encoded_dirname, compute_sha1_git_from_string(
                os.readlink(direntry.path)
            ), b"120000", True
        elif direntry.is_dir(follow_symlinks=False):
            yield encoded_dirname, compute_sha1_git_from_dir(
                direntry.path
            ), b"40000", False
        elif direntry.is_file(follow_symlinks=False):
            if direntry.stat(follow_symlinks=False).st_mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                bperms = b"100755"
            else:
                bperms = b"100644"
            yield encoded_dirname, compute_sha1_git_from_file(
                direntry.path
            ), bperms, True


def compute_sha1_git_from_dir(dirname: "str") -> "hashlib._Hash":
    # Directories receive an special treatment
    sorted_entries = sorted(
        process_dir_entries(dirname), key=lambda t: t[0] if t[3] else t[0] + b"/"
    )

    # Compute the number to be put there
    tree_size = 0
    for entry in sorted_entries:
        tree_size += len(entry[0]) + len(entry[1].digest()) + len(entry[2]) + 2

    # Now, the hash
    h = hashlib.sha1()
    h.update(b"tree ")
    h.update(str(tree_size).encode("ascii"))
    h.update(b"\0")
    for entry in sorted_entries:
        h.update(entry[2])
        h.update(b" ")
        h.update(entry[0])
        h.update(b"\0")
        h.update(entry[1].digest())

    return h


@functools.lru_cache(maxsize=128)
def compute_sha1_git_from_any(path: "str") -> "Tuple[str, str]":
    if os.path.exists(path):
        if os.path.isdir(path):
            return compute_sha1_git_from_dir(path).hexdigest(), "dir"
        else:
            return compute_sha1_git_from_file(path).hexdigest(), "cnt"

    raise FileNotFoundError(f"Unable to process path {path}")


# Next method has been borrowed from FlowMaps
def scantree(path: "PathLikePath") -> "Iterator[os.DirEntry[str]]":
    """Recursively yield DirEntry objects for given directory."""

    hasDirs = False
    for entry in os.scandir(path):
        # We are avoiding to enter in loops around '.' and '..'
        if entry.is_dir(follow_symlinks=False):
            if entry.name[0] != ".":
                hasDirs = True
        else:
            yield entry

    # We are leaving the dirs to the end
    if hasDirs:
        for entry in os.scandir(path):
            # We are avoiding to enter in loops around '.' and '..'
            if entry.is_dir(follow_symlinks=False) and entry.name[0] != ".":
                yield entry
                yield from scantree(cast("AbsPath", entry.path))


def ComputeDigestFromDirectory(
    dirname: "PathLikePath",
    digestAlgorithm: "str" = DEFAULT_DIGEST_ALGORITHM,
    bufferSize: "int" = DEFAULT_DIGEST_BUFFER_SIZE,
    repMethod: "FingerprintMethod" = stringifyDigest,
) -> "Fingerprint":
    """
    Accessory method used to compute the digest of an input directory,
    based on the names and digest of the files in the directory
    """
    cEntries: "MutableSequence[Tuple[bytes, bytes]]" = []
    # First, gather and compute all the files
    for entry in scantree(dirname):
        if entry.is_file():
            cEntries.append(
                (
                    os.path.relpath(entry.path, dirname).encode("utf-8"),
                    cast(
                        "bytes",
                        ComputeDigestFromFile(entry.path, repMethod=nullProcessDigest),
                    ),
                )
            )

    # Second, sort by the relative path, bytes encoded in utf-8
    cEntries = sorted(cEntries, key=lambda e: e[0])

    # Third, digest compute
    h = hashlib.new(digestAlgorithm)
    for cRelPathB, cDigest in cEntries:
        h.update(cRelPathB)
        h.update(cDigest)

    return repMethod(digestAlgorithm, h.digest())


def ComputeDigestFromGeneratedContentList(
    dirname: "PathLikePath",
    theValues: "Sequence[AbstractGeneratedContent]",
    digestAlgorithm: "str" = DEFAULT_DIGEST_ALGORITHM,
    bufferSize: "int" = DEFAULT_DIGEST_BUFFER_SIZE,
    repMethod: "FingerprintMethod" = stringifyDigest,
) -> "Fingerprint":
    """
    Accessory method used to compute the digest of an input directory,
    based on the names and digest of the files in the directory
    """
    cEntries: "MutableSequence[Tuple[bytes, bytes]]" = []
    # First, gather and compute all the files
    for theValue in theValues:
        if isinstance(theValue, GeneratedContent):
            cEntries.append(
                (
                    os.path.relpath(theValue.local, dirname).encode("utf-8"),
                    cast(
                        "bytes",
                        ComputeDigestFromFile(
                            theValue.local, repMethod=nullProcessDigest
                        ),
                    ),
                )
            )

    # Second, sort by the relative path, bytes encoded in utf-8
    cEntries = sorted(cEntries, key=lambda e: e[0])

    # Third, digest compute
    h = hashlib.new(digestAlgorithm)
    for cRelPathB, cDigest in cEntries:
        h.update(cRelPathB)
        h.update(cDigest)

    return repMethod(digestAlgorithm, h.digest())
