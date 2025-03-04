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
import sys
from typing import (
    cast,
    TYPE_CHECKING,
)

import data_url

from .misc import lazy_import

magic = lazy_import("magic")
# import magic

from .zipfile_path import ZipfilePath

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
        MaterializedContent,
        PathLikePath,
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
    thePath: "PathLikePath",
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
    thePath: "PathLikePath",
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


def MaterializedContent2AbstractGeneratedContent(
    mat_content: "MaterializedContent",
    preferredFilename: "Optional[RelPath]" = None,
    signatureMethod: "Optional[FingerprintMethod]" = nihDigester,
) -> "AbstractGeneratedContent":
    """
    This method generates either a GeneratedContent
    or a GeneratedDirectoryContent from a MaterializedContent
    """
    local = (
        mat_content.extrapolated_local
        if mat_content.extrapolated_local is not None
        else mat_content.local
    )
    if mat_content.kind == ContentKind.File:
        return GeneratedContent(
            local=local,
            uri=mat_content.licensed_uri,
            # This might be in the wrong representation
            signature=mat_content.fingerprint,
            preferredFilename=preferredFilename,
        )
    else:
        return GetGeneratedDirectoryContent(
            thePath=local,
            uri=mat_content.licensed_uri,
            preferredFilename=preferredFilename,
            signatureMethod=signatureMethod,
        )


def Path2AbstractGeneratedContent(
    content: "pathlib.Path",
    preferredFilename: "Optional[RelPath]" = None,
    signatureMethod: "Optional[FingerprintMethod]" = nihDigester,
) -> "AbstractGeneratedContent":
    """
    This method generates either a GeneratedContent
    or a GeneratedDirectoryContent from a MaterializedContent
    """
    if content.is_dir():
        return GetGeneratedDirectoryContent(
            thePath=content,
            preferredFilename=preferredFilename,
            signatureMethod=signatureMethod,
        )
    else:
        return GeneratedContent(
            local=content,
            signature=cast(
                "Optional[Fingerprint]",
                ComputeDigestFromFile(content, repMethod=signatureMethod),
            ),
            preferredFilename=preferredFilename,
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
                local=pathlib.Path(cwlDesc["path"]),
                signature=cast(
                    "Fingerprint",
                    ComputeDigestFromFile(cwlDesc["path"], repMethod=repMethod),
                ),
                secondaryFiles=secondaryFiles,
            )

        if matValue is not None:
            matValues.append(matValue)

    return matValues


def copy2_nofollow(src: "PathLikePath", dest: "PathLikePath") -> "None":
    shutil.copy2(src, dest, follow_symlinks=False)


def copy_nofollow(src: "PathLikePath", dest: "PathLikePath") -> "None":
    shutil.copy(src, dest, follow_symlinks=False)


def copytree_pathlib(
    src: "pathlib.Path",
    dest: "pathlib.Path",
    force_copy: "bool" = False,
    preserve_attrs: "bool" = True,
    no_merge: "bool" = True,
) -> None:
    assert src.is_dir()
    if dest.exists() and no_merge:
        shutil.rmtree(dest)

    if not dest.exists():
        dest.mkdir(parents=True, exist_ok=True)
    elif no_merge:
        raise FileExistsError(f"Directory exists: {dest.as_posix()}")

    for entry in os.scandir(src):
        if entry.is_dir(follow_symlinks=False):
            # Skip these directories
            if entry.name in (".", ".."):
                continue
            copytree_pathlib(
                src / entry.name,
                dest / entry.name,
                force_copy=force_copy,
                preserve_attrs=preserve_attrs,
                no_merge=no_merge,
            )
        else:
            link_or_copy_pathlib(
                src / entry.name,
                dest / entry.name,
                force_copy=force_copy,
                preserve_attrs=preserve_attrs,
                no_merge=no_merge,
            )

    # Last, but not the least important
    if preserve_attrs:
        shutil.copystat(src, dest)


def link_or_copy(
    src: "PathLikePath",
    dest: "PathLikePath",
    force_copy: "bool" = False,
    preserve_attrs: "bool" = True,
    no_merge: "bool" = True,
) -> None:
    link_or_copy_pathlib(
        src if isinstance(src, pathlib.Path) else pathlib.Path(src),
        dest if isinstance(dest, pathlib.Path) else pathlib.Path(dest),
        force_copy=force_copy,
        preserve_attrs=preserve_attrs,
        no_merge=no_merge,
    )


def link_or_copy_pathlib(
    src: "pathlib.Path",
    dest: "pathlib.Path",
    force_copy: "bool" = False,
    preserve_attrs: "bool" = True,
    no_merge: "bool" = True,
) -> None:
    assert (
        src.exists()
    ), f"File {src.as_posix()} must exist to be linked or copied {src.exists()} {src.is_symlink()}"

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
    link_condition = False
    try:
        link_condition = (
            not isinstance(src, ZipfilePath)
            and src.lstat().st_dev == dest_st_dev
            and not force_copy
        )
    except:
        pass
    if link_condition:
        try:
            if src.is_file():
                if dest_exists:
                    dest.unlink()
                # link_to appeared in Python 3.8
                # hardlink_to appeared in Python 3.10
                # dest.hardlink_to(src)
                os.link(src, dest)
            else:
                # Recursively hardlinking
                # as of https://stackoverflow.com/a/10778930
                if dest_exists and no_merge:
                    shutil.rmtree(dest)

                # TODO: study passing link_or_copy as copy_function
                if sys.version_info[:2] >= (3, 8):
                    shutil.copytree(  # pylint: disable=unexpected-keyword-arg
                        src,
                        dest,
                        copy_function=lambda s, d: link_or_copy(
                            s,
                            d,
                            force_copy=force_copy,
                            preserve_attrs=preserve_attrs,
                            no_merge=no_merge,
                        ),
                        dirs_exist_ok=not no_merge,
                    )  # type: ignore[arg-type]
                else:
                    copytree_pathlib(
                        src,
                        dest,
                        force_copy=force_copy,
                        preserve_attrs=preserve_attrs,
                        no_merge=no_merge,
                    )
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
            if isinstance(src, ZipfilePath):
                src.copy_to(dest, preserve_attrs=preserve_attrs)
            elif preserve_attrs:
                shutil.copy2(src, dest)
            else:
                shutil.copy(src, dest)
        else:
            # Recursively copying the content
            # as it is in a separated filesystem
            if dest_exists and no_merge:
                shutil.rmtree(dest)
            if isinstance(src, ZipfilePath):
                src.copy_to(dest, preserve_attrs=preserve_attrs)
            elif sys.version_info[:2] >= (3, 8):
                shutil.copytree(  # pylint: disable=unexpected-keyword-arg
                    src,
                    dest,
                    copy_function=copy2_nofollow if preserve_attrs else copy_nofollow,
                    dirs_exist_ok=not no_merge,
                )
            else:
                # TO BE REMOVED ON PYTHON 3.7 SUPPORT DEPRECATION
                import distutils.dir_util

                distutils.dir_util.copy_tree(
                    src.as_posix(), dest.as_posix(), preserve_mode=preserve_attrs
                )


def link_or_symlink_pathlib(
    src: "pathlib.Path",
    dest: "pathlib.Path",
    force_symlink: "bool" = False,
) -> None:
    assert (
        src.exists()
    ), f"File {src.as_posix()} must exist to be linked or copied {src.exists()} {src.is_symlink()}"

    if isinstance(src, ZipfilePath):
        raise Exception(f"Unable to symlink {src}, as it is within a ZIP archive")

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

    # Now, link or symlink
    link_condition = False
    try:
        link_condition = (
            not isinstance(src, ZipfilePath)
            and src.lstat().st_dev == dest_st_dev
            and not force_symlink
        )
    except:
        pass

    if link_condition:
        try:
            if src.is_file():
                if dest_exists:
                    dest.unlink()
                # link_to appeared in Python 3.8
                # hardlink_to appeared in Python 3.10
                # dest.hardlink_to(src)
                os.link(src, dest)
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

            force_symlink = True
    else:
        # Be sure to enable to symlink, to avoid a no-op
        force_symlink = True

    if force_symlink:
        # Symlinking the content
        if dest_exists:
            if dest.is_file():
                dest.unlink()
            else:
                shutil.rmtree(dest)

        dest.symlink_to(src)


def real_unlink_if_exists(the_path: "PathLikePath", fail_ok: "bool" = False) -> "None":
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
        # mime_type=mime_type, base64_encoded=True, data=content
        data_url.construct_data_url(mime_type, True, content),
    )
