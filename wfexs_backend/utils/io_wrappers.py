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

import hashlib
import io
import os
import quopri
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse
import uuid

from .misc import (
    lazy_import,
)

magic = lazy_import("magic")
# import magic

if TYPE_CHECKING:
    from typing import (
        IO,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Buffer,
    )

    from _typeshed import SupportsRead


class AbstractProxyIOWrapper(io.RawIOBase):
    """
    This class is used to compute the digestion of the read bytes of a stream on the fly
    """

    def __init__(
        self,
        stream: "Union[IO[bytes], io.RawIOBase]",
    ):
        self.stream = stream
        if hasattr(stream, "readinto") and callable(stream.readinto):
            self.shim_readinto = stream.readinto
        else:
            self.shim_readinto = self._fake_readinto

    def _fake_readinto(self, buf: "Buffer") -> "Optional[int]":
        mbuf = memoryview(buf)
        rbuf = self.stream.read(len(mbuf))
        if rbuf is None:
            return None

        len_rbuf = len(rbuf)
        mbuf[:len_rbuf] = rbuf
        return len_rbuf

    def close(self) -> "None":
        self.stream.close()

    @property
    def closed(self) -> "bool":
        return self.stream.closed

    def readable(self) -> "bool":
        return self.stream.readable()

    def tell(self) -> "int":
        return self.stream.tell()

    def writable(self) -> "bool":
        return False


class DigestIOWrapper(AbstractProxyIOWrapper):
    """
    This class is used to compute the digestion of the read bytes of a stream on the fly
    """

    def __init__(
        self,
        stream: "Union[IO[bytes], io.RawIOBase]",
        algo: "str" = "sha256",
    ):
        super().__init__(stream)

        self.h: "hashlib._Hash" = hashlib.new(algo)

    def readinto(self, buf: "Buffer") -> "int":
        numread: "Optional[int]" = None
        while numread is None:
            numread = self.shim_readinto(buf)

        if numread > 0:
            # Update the hash if something was read
            self.h.update(memoryview(buf)[0:numread])

        return numread

    def digest(self) -> "bytes":
        return self.h.digest()

    def hexdigest(self) -> "str":
        return self.h.hexdigest()


class MIMETypeIOWrapper(AbstractProxyIOWrapper):
    """
    This class is used to compute the MIME type of a stream on the fly
    """

    def __init__(
        self,
        stream: "Union[IO[bytes], io.RawIOBase]",
    ):
        super().__init__(stream)
        self.found_mime: "Optional[str]" = None
        self.prefetched: "Optional[bytes]" = None
        self.pos_prefetched = 0

    def readinto(self, buf: "Buffer") -> "Optional[int]":
        mbuf = memoryview(buf)
        if self.prefetched is not None and self.pos_prefetched < len(self.prefetched):
            chunksize = len(self.prefetched) - self.pos_prefetched
            limitread = len(mbuf) < chunksize
            if limitread:
                chunksize = len(mbuf)

            mbuf[:chunksize] = self.prefetched[
                self.pos_prefetched : self.pos_prefetched + chunksize
            ]
            self.pos_prefetched += chunksize

            if not limitread:
                otherpart = self.stream.read(len(mbuf) - chunksize)
                if otherpart is not None:
                    mbuf[chunksize : chunksize + len(otherpart)] = otherpart
                    chunksize += len(otherpart)

            return chunksize

        return self.shim_readinto(buf)

    def _compute_mime(self) -> "None":
        if self.prefetched is None:
            while self.prefetched is None:
                self.prefetched = self.stream.read(4096)
            self.pos_prefetched = 0
            self.found_mime = magic.from_buffer(self.prefetched, mime=True)

    def mime(self) -> "str":
        self._compute_mime()

        return (
            "application/octet-stream" if self.found_mime is None else self.found_mime
        )


class LimitedStreamIOWrapper(AbstractProxyIOWrapper):
    """
    This class is used to provide chunked uploads from a stream
    """

    def __init__(
        self,
        stream: "Union[IO[bytes], io.RawIOBase]",
        maxreadsize: "int",
    ):
        super().__init__(stream)
        self.remainingbytes: "int" = maxreadsize

    def readinto(self, buf: "Buffer") -> "int":
        numread: "int" = 0
        if self.remainingbytes > 0:
            numbytes = len(buf)  # type: ignore[arg-type]
            readbuf: "Buffer"
            if numbytes > self.remainingbytes:
                numbytes = self.remainingbytes
                readbuf = bytearray(numbytes)
            else:
                readbuf = buf

            u_numread: "Optional[int]" = None
            while u_numread is None:
                u_numread = self.shim_readinto(readbuf)

            numread = u_numread
            if readbuf != buf:
                assert isinstance(readbuf, bytearray)
                memoryview(buf)[0:numread] = readbuf[0:numread]

            if numread > 0:
                self.remainingbytes -= numread
            else:
                # Stop when nothing to be read is left
                self.remainingbytes = 0

        return numread


class MultipartFile(NamedTuple):
    filename: "str"
    mime: "str"
    stream: "SupportsRead[bytes]"
    size: "Optional[int]"


class MultipartEncoderIOWrapper(io.RawIOBase):
    """
    This implementation is slightly inspired on https://stackoverflow.com/a/77323411
    """

    def __init__(
        self,
        fields: "Sequence[Tuple[str, Sequence[Union[str, MultipartFile]]]]",
        boundary: "Optional[str]" = None,
    ):
        # Safe boundaries
        self.boundary = (
            uuid.uuid4().hex
            if boundary is None
            else urllib.parse.quote(boundary, encoding="utf-8")
        )

        self._set_fields(fields)

    @property
    def content_type(self) -> "str":
        return f"multipart/form-data; boundary={self.boundary}"

    def _set_fields(
        self, fields: "Sequence[Tuple[str, Sequence[Union[str, MultipartFile]]]]"
    ) -> "None":
        self.fields = fields
        self.i_field = 0

        self.current_field_name: "Optional[str]" = None
        self.current_field_value: "Optional[Sequence[Union[str, MultipartFile]]]" = None
        self.current_value: "Optional[Union[str, MultipartFile]]" = None
        self.current_field_value_index = 0

        self.header: "Optional[bytes]" = None
        self.header_bytes_emitted = 0
        self.stream_bytes_emitted = 0
        self.emitted_footer = False

    def _current_field_header(self) -> "bytes":
        assert self.current_field_name is not None
        assert self.current_value is not None

        if isinstance(self.current_value, str):
            return (
                f"--{self.boundary}\r\n"
                f'Content-Disposition: form-data; name="{urllib.parse.quote(self.current_field_name, safe=" ", encoding="utf-8")}"\r\n'
                "Content-Type: text/plain;charset=UTF-8\r\n"
                "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
            ).encode("ascii") + quopri.encodestring(self.current_value.encode("utf-8"))
        elif isinstance(self.current_value, MultipartFile):
            return (
                f"--{self.boundary}\r\n"
                f'Content-Disposition: form-data; name="{urllib.parse.quote(self.current_field_name, safe=" ", encoding="utf-8")}"; filename="{urllib.parse.quote(self.current_value.filename, safe=" ", encoding="utf-8")}"\r\n'
                f"Content-Type: {self.current_value.mime}\r\n\r\n"
            ).encode("ascii")
        else:
            return ""

    @property
    def footer(self) -> "bytes":
        return f"\r\n--{self.boundary}--\r\n".encode("ascii")

    def readinto(self, buf: "Buffer") -> "int":
        mbuf = memoryview(buf)
        bufsize = len(mbuf)
        bufpos = 0

        while bufpos < bufsize and (
            self.i_field < len(self.fields)
            or self.header is None
            or self.header_bytes_emitted < len(self.header)
        ):
            if self.i_field < len(self.fields):
                # Assure we are processing the field
                if self.current_field_name is None:
                    self.current_field_name, self.current_field_value = self.fields[
                        self.i_field
                    ]
                    self.current_field_value_index = -1
                    self.current_value = None

                assert self.current_field_value is not None

                # Assure we are pointing to a value from that field
                if self.current_value is None:
                    self.current_field_value_index += 1
                    self.header = None
                    if self.current_field_value_index >= len(self.current_field_value):
                        self.i_field += 1
                        self.current_field_name = None
                        self.current_field_value = None
                        continue

                    self.current_value = self.current_field_value[
                        self.current_field_value_index
                    ]
                    self.stream_bytes_emitted = 0

                # Assure the header is populated
                if self.header is None:
                    self.header = (
                        b"\r\n"
                        if self.i_field > 0 or self.current_field_value_index > 0
                        else b""
                    )
                    self.header += self._current_field_header()
                    self.header_bytes_emitted = 0

            elif self.header is None:
                self.header = self.footer
                self.header_bytes_emitted = 0
                self.emitted_footer = True

            # Can we emit header bytes?
            if self.header_bytes_emitted < len(self.header):
                copysize = len(self.header) - self.header_bytes_emitted

                if bufpos + copysize > bufsize:
                    copysize = bufsize - bufpos

                mbuf[bufpos : bufpos + copysize] = self.header[
                    self.header_bytes_emitted : self.header_bytes_emitted + copysize
                ]
                bufpos += copysize
                self.header_bytes_emitted += copysize

            # Can we emit body bytes?
            if self.header_bytes_emitted == len(self.header) and bufpos < bufsize:
                if self.emitted_footer:
                    # Nothing to offer
                    break

                if isinstance(self.current_value, str):
                    # Maybe something new to offer
                    self.current_value = None
                    continue

                if isinstance(self.current_value, MultipartFile):
                    tempbufsize = bufsize - bufpos
                    # This is for capped streams
                    if (
                        self.current_value.size is not None
                        and tempbufsize + self.stream_bytes_emitted
                        > self.current_value.size
                    ):
                        tempbufsize = (
                            self.current_value.size - self.stream_bytes_emitted
                        )

                    tempbuf = self.current_value.stream.read(tempbufsize)
                    numread = len(tempbuf)
                    if numread > 0:
                        mbuf[bufpos : bufpos + numread] = tempbuf
                        bufpos += numread
                        self.stream_bytes_emitted += numread
                        if (
                            self.current_value.size is not None
                            and self.stream_bytes_emitted >= self.current_value.size
                        ):
                            # Read until the limit is reached
                            self.current_value = None
                    else:
                        # Maybe something to offer
                        self.current_value = None

        return bufpos
