#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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

import os
import shutil
from typing import cast, Any, List, Mapping, Optional, Sequence, Union

from ..common import AbsPath, AbstractGeneratedContent, ContentKind
from ..common import ExpectedOutput, Fingerprint, GeneratedContent
from ..common import GeneratedDirectoryContent, LicensedURI, RelPath

from .digests import nihDigester, ComputeDigestFromDirectory
from .digests import ComputeDigestFromFile, ComputeDigestFromGeneratedContentList

def GetGeneratedDirectoryContent(
    thePath: AbsPath,
    uri: Optional[LicensedURI] = None,
    preferredFilename: Optional[RelPath] = None,
    signatureMethod = None
) -> GeneratedDirectoryContent:
    """
    The signatureMethod tells whether to generate a signature and fill-in
    the new signature element from GeneratedDirectoryContent tuple
    """
    theValues : List[Union[AbstractGeneratedContent, GeneratedContent, GeneratedDirectoryContent]] = []
    with os.scandir(thePath) as itEntries:
        for entry in itEntries:
            # Hidden files are skipped by default
            if not entry.name.startswith('.'):
                theValue : Optional[Union[AbstractGeneratedContent, GeneratedContent, GeneratedDirectoryContent]] = None
                if entry.is_file():
                    entry_path = cast(AbsPath, entry.path)
                    theValue = GeneratedContent(
                        local=entry_path,
                        # uri=None, 
                        signature=cast(Fingerprint, ComputeDigestFromFile(entry_path, repMethod=signatureMethod))
                    )
                elif entry.is_dir():
                    entry_path = cast(AbsPath, entry.path)
                    theValue = GetGeneratedDirectoryContent(entry_path, signatureMethod=signatureMethod)

                if theValue is not None:
                    theValues.append(theValue)
    
    # As this is a heavy operation, do it only when it is requested
    signature : Optional[Fingerprint]
    if callable(signatureMethod):
        signature = cast(Fingerprint, ComputeDigestFromDirectory(thePath, repMethod=signatureMethod))
    else:
        signature = None
    
    return GeneratedDirectoryContent(
        local=thePath,
        uri=uri,
        preferredFilename=preferredFilename,
        values=cast(Sequence[AbstractGeneratedContent], theValues),
        signature=signature
    )

def GetGeneratedDirectoryContentFromList(
    thePath: AbsPath,
    theValues: Sequence[AbstractGeneratedContent],
    uri: Optional[LicensedURI] = None,
    preferredFilename: Optional[RelPath] = None,
    secondaryFiles: Optional[Sequence[AbstractGeneratedContent]] = None,
    signatureMethod = None
) -> GeneratedDirectoryContent:
    """
    The signatureMethod tells whether to generate a signature and fill-in
    the new signature element from GeneratedDirectoryContent tuple
    """
    
    # As this is a heavy operation, do it only when it is requested
    signature : Optional[Fingerprint]
    if callable(signatureMethod):
        signature = cast(Fingerprint, ComputeDigestFromGeneratedContentList(thePath, theValues, repMethod=signatureMethod))
    else:
        signature = None
    
    return GeneratedDirectoryContent(
        local=thePath,
        uri=uri,
        preferredFilename=preferredFilename,
        values=theValues,
        signature=signature,
        secondaryFiles=secondaryFiles
    )


CWLClass2WfExS = {
    'Directory': ContentKind.Directory,
    'File': ContentKind.File
    # '???': ContentKind.Value
}


def CWLDesc2Content(
    cwlDescs: Union[Mapping[str, Any], List[Mapping[str, Any]]],
    logger,
    expectedOutput: Optional[ExpectedOutput] = None,
    doGenerateSignatures: bool = False
) -> Union[List[bool], List[str], List[int], List[float], List[GeneratedContent], List[GeneratedDirectoryContent]]:
    """
    """
    matValues = []

    if not isinstance(cwlDescs, list):
        cwlDescs = [cwlDescs]
    
    if doGenerateSignatures:
        repMethod = nihDigester
    else:
        repMethod = None
    
    for cwlDesc in cwlDescs:
        foundKind = CWLClass2WfExS.get(cwlDesc['class'])
        if (expectedOutput is not None) and foundKind != expectedOutput.kind:
            logger.warning("For output {} obtained kind does not match ({} vs {})".format(expectedOutput.name, expectedOutput.kind, foundKind))
        
        # What to do with auxiliary/secondary files?
        secondaryFilesRaw = cwlDesc.get('secondaryFiles')
        if secondaryFilesRaw:
            secondaryFiles = CWLDesc2Content(secondaryFilesRaw, logger, doGenerateSignatures=doGenerateSignatures)
        else:
            secondaryFiles = None

        matValue : Optional[Union[GeneratedDirectoryContent, GeneratedContent]] = None
        if foundKind == ContentKind.Directory:
            theValues = CWLDesc2Content(cwlDesc['listing'], logger=logger, doGenerateSignatures=doGenerateSignatures)
            matValue = GetGeneratedDirectoryContentFromList(
                cwlDesc['path'],
                theValues,
                # TODO: Generate URIs when it is advised
                # uri=None,
                preferredFilename=None if expectedOutput is None else expectedOutput.preferredFilename,
                secondaryFiles=secondaryFiles,
                signatureMethod=repMethod
            )
        elif foundKind == ContentKind.File:
            matValue = GeneratedContent(
                local=cwlDesc['path'],
                signature=ComputeDigestFromFile(cwlDesc['path'], repMethod=repMethod),
                secondaryFiles=secondaryFiles
            )
        
        if matValue is not None:
            matValues.append(matValue)
            

    return matValues

def link_or_copy(src: Union[RelPath, AbsPath], dest: Union[RelPath, AbsPath]):
    # We should not deal with symlinks
    src = cast(AbsPath, os.path.realpath(src))
    
    # First, check whether inputs and content
    # are in the same filesystem
    # as of https://unix.stackexchange.com/a/44250
    dest_exists = os.path.exists(dest)
    if dest_exists:
        dest_st_dev = os.lstat(dest).st_dev
    else:
        dest_st_dev = os.lstat(os.path.dirname(dest)).st_dev
    if os.lstat(src).st_dev == dest_st_dev:
        if os.path.isfile(src):
            if dest_exists:
                os.unlink(dest)
            os.link(src, dest)
        else:
            # Recursively hardlinking
            # as of https://stackoverflow.com/a/10778930
            if dest_exists:
                shutil.rmtree(dest)
            shutil.copytree(src, dest, copy_function=os.link)
    elif os.path.isfile(src):
        # Copying the content
        # as it is in a separated filesystem
        if dest_exists:
            os.unlink(dest)
        shutil.copy2(src, dest)
    else:
        # Recursively copying the content
        # as it is in a separated filesystem
        if dest_exists:
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        