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

import logging
import os
import pathlib
import shutil
from typing import (
    cast,
    TYPE_CHECKING,
)

import data_url

from .misc import lazy_import

magic = lazy_import("magic")
# import magic

from ..common import (
    ContentKind,
    GeneratedContent,
    GeneratedDirectoryContent,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Union,
    )

    from ..common import (
        AbsPath,
        AbstractGeneratedContent,
        AnyPath,
        ExpectedOutput,
        Fingerprint,
        LicensedURI,
        RelPath,
        URIType,
    )

    from .digests import (
        FingerprintMethod,
    )

from .digests import (
    nihDigester,
    ComputeDigestFromDirectory,
    ComputeDigestFromFile,
    ComputeDigestFromGeneratedContentList,
)


def GetGeneratedDirectoryContent(
    thePath: "Union[AbsPath, os.PathLike[str]]",
    uri: "Optional[LicensedURI]" = None,
    preferredFilename: "Optional[RelPath]" = None,
    signatureMethod: "Optional[FingerprintMethod]" = None,
) -> "GeneratedDirectoryContent":
    """
    The signatureMethod tells whether to generate a signature and fill-in
    the new signature element from GeneratedDirectoryContent tuple
    """
    theValues: "MutableSequence[AbstractGeneratedContent]" = []
    with os.scandir(thePath) as itEntries:
        for entry in itEntries:
            # Hidden files are skipped by default
            if not entry.name.startswith("."):
                theValue: "Optional[AbstractGeneratedContent]" = None
                if entry.is_file():
                    entry_path = pathlib.Path(entry.path)
                    theValue = GeneratedContent(
                        local=entry_path,
                        # uri=None,
                        signature=cast(
                            "Fingerprint",
                            ComputeDigestFromFile(
                                entry_path, repMethod=signatureMethod
                            ),
                        ),
                    )
                elif entry.is_dir():
                    entry_path = pathlib.Path(entry.path)
                    theValue = GetGeneratedDirectoryContent(
                        entry_path, signatureMethod=signatureMethod
                    )

                if theValue is not None:
                    theValues.append(theValue)

    # As this is a heavy operation, do it only when it is requested
    signature: "Optional[Fingerprint]"
    if callable(signatureMethod):
        signature = ComputeDigestFromDirectory(thePath, repMethod=signatureMethod)
    else:
        signature = None

    return GeneratedDirectoryContent(
        local=thePath if isinstance(thePath, pathlib.Path) else pathlib.Path(thePath),
        uri=uri,
        preferredFilename=preferredFilename,
        values=theValues,
        signature=signature,
    )


def GetGeneratedDirectoryContentFromList(
    thePath: "Union[AbsPath, os.PathLike[str]]",
    theValues: "Sequence[AbstractGeneratedContent]",
    uri: "Optional[LicensedURI]" = None,
    preferredFilename: "Optional[RelPath]" = None,
    secondaryFiles: "Optional[Sequence[AbstractGeneratedContent]]" = None,
    signatureMethod: "Optional[FingerprintMethod]" = None,
) -> "GeneratedDirectoryContent":
    """
    The signatureMethod tells whether to generate a signature and fill-in
    the new signature element from GeneratedDirectoryContent tuple
    """

    # As this is a heavy operation, do it only when it is requested
    signature: "Optional[Fingerprint]"
    if callable(signatureMethod):
        signature = ComputeDigestFromGeneratedContentList(
            thePath, theValues, repMethod=signatureMethod
        )
    else:
        signature = None

    return GeneratedDirectoryContent(
        local=thePath if isinstance(thePath, pathlib.Path) else pathlib.Path(thePath),
        uri=uri,
        preferredFilename=preferredFilename,
        values=theValues,
        signature=signature,
        secondaryFiles=secondaryFiles,
    )


CWLClass2WfExS = {
    "Directory": ContentKind.Directory,
    "File": ContentKind.File
    # '???': ContentKind.Value
}


def CWLDesc2Content(
    cwlDescs: "Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]",
    logger: "logging.Logger",
    expectedOutput: "Optional[ExpectedOutput]" = None,
    doGenerateSignatures: "bool" = False,
) -> "Sequence[AbstractGeneratedContent]":
    """ """
    matValues: "MutableSequence[AbstractGeneratedContent]" = []

    if not isinstance(cwlDescs, list):
        cwlDescs = [cast("Mapping[str, Any]", cwlDescs)]

    if doGenerateSignatures:
        repMethod = nihDigester
    else:
        repMethod = None

    for cwlDesc in cwlDescs:
        foundKind = CWLClass2WfExS.get(cwlDesc["class"])
        if (expectedOutput is not None) and foundKind != expectedOutput.kind:
            logger.warning(
                "For output {} obtained kind does not match ({} vs {})".format(
                    expectedOutput.name, expectedOutput.kind, foundKind
                )
            )

        # What to do with auxiliary/secondary files?
        secondaryFilesRaw = cwlDesc.get("secondaryFiles")
        secondaryFiles: "Optional[Sequence[AbstractGeneratedContent]]" = None
        if secondaryFilesRaw:
            secondaryFiles = CWLDesc2Content(
                secondaryFilesRaw, logger, doGenerateSignatures=doGenerateSignatures
            )
        else:
            secondaryFiles = None

        matValue: "Optional[AbstractGeneratedContent]" = None
        if foundKind == ContentKind.Directory:
            theValues = CWLDesc2Content(
                cwlDesc["listing"],
                logger=logger,
                doGenerateSignatures=doGenerateSignatures,
            )
            matValue = GetGeneratedDirectoryContentFromList(
                cwlDesc["path"],
                theValues,
                # TODO: Generate URIs when it is advised
                # uri=None,
                preferredFilename=None
                if expectedOutput is None
                else expectedOutput.preferredFilename,
                secondaryFiles=secondaryFiles,
                signatureMethod=repMethod,
            )
        elif foundKind == ContentKind.File:
            matValue = GeneratedContent(
                local=cwlDesc["path"],
                signature=cast(
                    "Fingerprint",
                    ComputeDigestFromFile(cwlDesc["path"], repMethod=repMethod),
                ),
                secondaryFiles=secondaryFiles,
            )

        if matValue is not None:
            matValues.append(matValue)

    return matValues


def copy2_nofollow(
    src: "Union[str, os.PathLike[str]]", dest: "Union[str, os.PathLike[str]]"
) -> "None":
    shutil.copy2(src, dest, follow_symlinks=False)


def link_or_copy(
    src: "Union[AnyPath, os.PathLike[str]]",
    dest: "Union[AnyPath, os.PathLike[str]]",
    force_copy: "bool" = False,
) -> None:
    link_or_copy_pathlib(pathlib.Path(src), pathlib.Path(dest), force_copy=force_copy)


def link_or_copy_pathlib(
    src: "pathlib.Path", dest: "pathlib.Path", force_copy: "bool" = False
) -> None:
    assert (
        src.exists()
    ), f"File {src.as_posix()} must exist to be linked or copied {src.exists()} {src.exists(follow_symlinks=False)}"

    # We should not deal with symlinks
    src = src.resolve()
    dest = dest.resolve()
    # Avoid losing everything by overwriting itself
    dest_exists = dest.exists()
    if dest_exists and src.samefile(dest):
        return

    # First, check whether inputs and content
    # are in the same filesystem
    # as of https://unix.stackexchange.com/a/44250
    dest_or_ancestor_exists = dest_exists
    dest_or_ancestor = dest
    while not dest_or_ancestor_exists:
        dest_or_ancestor = dest_or_ancestor.parent
        dest_or_ancestor_exists = dest_or_ancestor.exists()
    dest_st_dev = dest_or_ancestor.lstat().st_dev

    # It could be a subtree of not existing directories
    if not dest_exists:
        dest_parent = dest.parent
        if not dest_parent.is_dir():
            dest_parent.mkdir(parents=True)

    # Now, link or copy
    if src.lstat().st_dev == dest_st_dev and not force_copy:
        try:
            if src.is_file():
                if dest_exists:
                    dest.unlink()
                dest.hardlink_to(src)
            else:
                # Recursively hardlinking
                # as of https://stackoverflow.com/a/10778930
                if dest_exists:
                    shutil.rmtree(dest)

                # TODO: study passing link_or_copy as copy_function
                shutil.copytree(src, dest, copy_function=link_or_copy)  # type: ignore[arg-type]
        except OSError as ose:
            # Even when we are detecting whether it is the same
            # device, it can happen both paths are in different
            # bind mounts, which forbid hard links
            if ose.errno != 18:
                if ose.errno == 1 and src.is_file():
                    try:
                        with src.open(mode="rb") as dummy:
                            readable = dummy.readable()
                    except OSError as dummy_err:
                        readable = False
                else:
                    # Too difficult to guess
                    readable = False
            else:
                readable = True

            if not readable:
                raise ose

            force_copy = True
    else:
        # Be sure to enable to copy, to avoid a no-op
        force_copy = True

    if force_copy:
        if src.is_file():
            # Copying the content
            # as it is in a separated filesystem
            if dest_exists:
                dest.unlink()
            shutil.copy2(src, dest)
        else:
            # Recursively copying the content
            # as it is in a separated filesystem
            if dest_exists:
                shutil.rmtree(dest)
            shutil.copytree(src, dest, copy_function=copy2_nofollow)


def real_unlink_if_exists(
    the_path: "Union[AnyPath, os.PathLike[str]]", fail_ok: "bool" = False
) -> "None":
    if os.path.lexists(the_path):
        try:
            canonical_to_be_erased = os.path.realpath(the_path)
            if os.path.exists(canonical_to_be_erased):
                os.unlink(canonical_to_be_erased)
        except Exception as e:
            if fail_ok:
                raise e
        try:
            os.unlink(the_path)
        except Exception as e:
            if fail_ok:
                raise e
    elif os.path.exists(the_path):
        try:
            os.unlink(the_path)
        except Exception as e:
            if fail_ok:
                raise e


def bin2dataurl(content: "bytes") -> "URIType":
    mime_type = magic.from_buffer(content, mime=True)

    if mime_type is None:
        mime_type = "application/octet-stream"

    return cast(
        "URIType",
        data_url.construct_data_url(
            mime_type=mime_type, base64_encode=True, data=content
        ),
    )
