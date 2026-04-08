#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2026 Barcelona Supercomputing Center (BSC), Spain
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

import datetime
import inspect
import io
import json
import logging
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
    )

    from typing_extensions import (
        Final,
    )

    import pathlib

    from .common import (
        AbsPath,
        AnyPath,
        ContainerType,
        ExitVal,
        LicenceDescription,
        MarshallingStatus,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        StagedSetup,
        SymbolicName,
        TRS_Workflow_Descriptor,
        URIType,
        WfExSInstanceId,
    )

    from .utils.passphrase_wrapper import (
        WfExSPassphraseGenerator,
    )

    from crypt4gh.header import CompoundKey

import crypt4gh.lib
import crypt4gh.keys.kdf

from RWFileLock import (
    LockError,
    RWFileLock,
)

from .common import (
    AbstractWfExSException,
    DEFAULT_FUSERMOUNT_CMD,
)

from .encrypted_fs import (
    DEFAULT_ENCRYPTED_FS_CMD,
    DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT,
    DEFAULT_ENCRYPTED_FS_TYPE,
    ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS,
    EncryptedFSType,
)

from .utils.misc import (
    config_validate,
    DatetimeEncoder,
    jsonFilterDecodeFromStream,
)

from .workflow_engines import (
    WORKDIR_META_RELDIR,
    WORKDIR_WORKFLOW_META_FILE,
)


class WorkdirException(AbstractWfExSException):
    pass


class Workdir:
    ID_JSON_FILENAME: "Final[str]" = ".id.json"
    LOCKFILE_PREFIX: "Final[str]" = "._lock_"
    LOCKFILE_MOUNT: "Final[str]" = LOCKFILE_PREFIX + "_mount"

    WORKDIR_PASSPHRASE_FILE: "Final[RelPath]" = cast("RelPath", ".passphrase")

    FUSE_SYSTEM_CONF: "Final[str]" = "/etc/fuse.conf"

    _NotInitialized: "ClassVar[bool]" = True
    DefaultEncfsCmd: "ClassVar[AnyPath]"
    DefaultEncfsType: "ClassVar[EncryptedFSType]"
    DefaultPrivKey: "ClassVar[bytes]"
    DefaultPubKey: "ClassVar[bytes]"
    EncfsIdleMinutes: "ClassVar[int]"
    FusermountCmd: "ClassVar[AnyPath]"

    @classmethod
    def InitFromConfig(
        cls,
        default_priv_key: "bytes",
        default_pub_key: "bytes",
        logger: "logging.Logger",
        encfs_sect: "Optional[Mapping[str, Any]]" = None,
    ) -> "AnyPath":
        cls._NotInitialized = False
        cls.DefaultPrivKey = default_priv_key
        cls.DefaultPubKey = default_pub_key

        if encfs_sect is None:
            encfs_sect = {}
        encfs_type_str: "Optional[str]" = encfs_sect.get(
            "type", DEFAULT_ENCRYPTED_FS_TYPE
        )
        assert encfs_type_str is not None
        try:
            encfs_type = EncryptedFSType(encfs_type_str)
        except:
            errmsg = f"Invalid default encryption filesystem {encfs_type_str}"
            logger.error(errmsg)
            raise WorkdirException(errmsg)
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            errmsg = f"FIXME: Default encryption filesystem {encfs_type} mount procedure is not implemented"
            logger.fatal(errmsg)
            raise WorkdirException(errmsg)
        cls.DefaultEncfsType = encfs_type

        cls.DefaultEncfsCmd = encfs_sect.get(
            "command", DEFAULT_ENCRYPTED_FS_CMD[cls.DefaultEncfsType]
        )
        abs_encfs_cmd = shutil.which(cls.DefaultEncfsCmd)
        if abs_encfs_cmd is None:
            errmsg = f"FUSE filesystem command {cls.DefaultEncfsCmd}, needed by {encfs_type}, was not found. Please install it if you are going to use a secured staged workdir"
            logger.error(errmsg)
        else:
            cls.DefaultEncfsCmd = cast("AbsPath", abs_encfs_cmd)

        fusermount_cmd = cast(
            "AnyPath", encfs_sect.get("fusermount_command", DEFAULT_FUSERMOUNT_CMD)
        )
        abs_fusermount_cmd = shutil.which(fusermount_cmd)
        if abs_fusermount_cmd is None:
            logger.error(f"FUSE fusermount command {fusermount_cmd} not found")
            cls.FusermountCmd = cast("RelPath", fusermount_cmd)
        else:
            cls.FusermountCmd = cast("AbsPath", abs_fusermount_cmd)

        cls.EncfsIdleMinutes = encfs_sect.get("idle", DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT)

        return cls.FusermountCmd

    def __init__(
        self,
        pass_gen: "WfExSPassphraseGenerator",
        uniqueRawWorkDir: "pathlib.Path",
        instanceId: "Optional[WfExSInstanceId]" = None,
        nickname: "Optional[str]" = None,
        orcids: "Optional[Sequence[str]]" = [],
        create_ok: "bool" = False,
    ):
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        if self._NotInitialized:
            raise WorkdirException(
                "Default values were not initialised (usually from WfExSBackend) yet"
            )

        """
        This method returns the absolute path to the raw working directory
        """
        uniqueRawWorkDir = uniqueRawWorkDir.absolute()

        self.pass_gen = pass_gen

        # TODO: Add some validation about the working directory
        id_json_path = uniqueRawWorkDir / self.ID_JSON_FILENAME
        id_json_path_lock = id_json_path.with_name(
            self.LOCKFILE_PREFIX + id_json_path.name
        )
        self.just_new: "bool" = False
        creation: "Optional[datetime.datetime]"
        if not uniqueRawWorkDir.exists():
            if not create_ok:
                raise WorkdirException(
                    f"Creation of {uniqueRawWorkDir} is not allowed by parameter"
                )

            uniqueRawWorkDir.mkdir(parents=True, exist_ok=True)
            self.just_new = True
            if instanceId is None:
                instanceId = cast("WfExSInstanceId", uniqueRawWorkDir.name)
            if nickname is None:
                nickname = pass_gen.generate_nickname()
            creation = datetime.datetime.now(tz=datetime.timezone.utc)
            with id_json_path_lock.open(mode="w+b") as idL:
                wlock = RWFileLock(idL)
                if orcids is None:
                    orcids = []
                with wlock.exclusive_blocking_lock():
                    id_json_path_tmp = tempfile.NamedTemporaryFile(
                        mode="w+t",
                        encoding="utf-8",
                        dir=uniqueRawWorkDir.as_posix(),
                        # We cannot use delete_on_close as it was introduced in Python 3.12
                        delete=False,
                    )
                    try:
                        idNick = {
                            "instance_id": instanceId,
                            "nickname": nickname,
                            "creation": creation,
                            "orcids": orcids,
                        }
                        json.dump(idNick, id_json_path_tmp, cls=DatetimeEncoder)
                        id_json_path_tmp.close()
                        shutil.move(id_json_path_tmp.name, id_json_path)
                        id_json_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                    finally:
                        if os.path.exists(id_json_path_tmp.name):
                            os.unlink(id_json_path_tmp.name)
        elif id_json_path.exists():
            with id_json_path_lock.open(mode="w+b") as iL:
                rlock = RWFileLock(iL)
                with rlock.shared_blocking_lock(), id_json_path.open(
                    mode="r", encoding="utf-8"
                ) as iH:
                    idNick = jsonFilterDecodeFromStream(iH)
                    instanceId = cast("WfExSInstanceId", idNick["instance_id"])
                    nickname = cast("str", idNick.get("nickname", instanceId))
                    creation = cast(
                        "Optional[datetime.datetime]", idNick.get("creation")
                    )
                    orcids = cast("Sequence[str]", idNick.get("orcids", []))

            # This file should not change
            if creation is None:
                creation = datetime.datetime.fromtimestamp(
                    id_json_path.stat().st_ctime
                ).astimezone()
        else:
            instanceId = cast("WfExSInstanceId", uniqueRawWorkDir.name)
            nickname = instanceId
            creation = None
            orcids = []

        assert orcids is not None

        self.raw_work_dir: "pathlib.Path" = uniqueRawWorkDir
        self.instance_id: "WfExSInstanceId" = instanceId
        self.nickname: "str" = nickname
        self.orcids: "Sequence[str]" = orcids

        if creation is None:
            # Just guessing
            w_m_path = (
                uniqueRawWorkDir / WORKDIR_META_RELDIR / WORKDIR_WORKFLOW_META_FILE
            )
            if w_m_path.exists():
                # This is valid for unencrypted working directories
                reference_path = w_m_path
            elif self.workdir_passphrase_file.exists():
                # This is valid for encrypted working directories
                reference_path = self.workdir_passphrase_file
            else:
                # This is the poor default
                reference_path = uniqueRawWorkDir

            creation = datetime.datetime.fromtimestamp(
                reference_path.stat().st_ctime
            ).astimezone()

        self.creation: "datetime.datetime" = creation

        self.enc_work_dir: "Optional[pathlib.Path]" = None
        self.work_dir: "Optional[pathlib.Path]" = None
        self.allow_other: "bool" = False

        self.encfs_type: "Optional[EncryptedFSType]" = None
        self.encfsCond: "Optional[threading.Condition]" = None
        self.encfsThread: "Optional[threading.Thread]" = None
        self.lmL: "Optional[IO[bytes]]" = None
        self.lmlock: "Optional[RWFileLock]" = None
        self.do_unmount = False
        self.was_setup = False
        self.was_init = False

    @property
    def workdir_passphrase_file(self) -> "pathlib.Path":
        return self.raw_work_dir / self.WORKDIR_PASSPHRASE_FILE

    def isSecure(self) -> "bool":
        return self.workdir_passphrase_file.exists()

    def _writePassphrase(
        self,
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        public_key_filenames: "Optional[Sequence[pathlib.Path]]" = None,
        passphrase_length: "int" = 4,
    ) -> "Tuple[EncryptedFSType, AnyPath, str, Sequence[bytes]]":
        """
        This method generates a random passphrase, which is stored
        in a crypt4gh encrypted file (along with the FUSE filesystem used)
        using either the default WfExS-backend public key, or the public
        keys stored in the files provided as a parameter.
        It returns the FUSE filesystem, the command to be used to mount,
        the generated passphrase (to be consumed in memory) and the list
        of public keys used to encrypt the passphrase file,
        which can be used later for some additional purposes.
        """
        if passphrase_length <= 0:
            passphrase_length = 4

        secureWorkdirPassphrase = self.pass_gen.generate_passphrase_random(
            passphrase_length=passphrase_length,
        )
        clearF = io.BytesIO(
            (self.DefaultEncfsType.value + "=" + secureWorkdirPassphrase).encode(
                "utf-8"
            )
        )

        if private_key_passphrase is None:
            private_key_passphrase_r = ""
        else:
            private_key_passphrase_r = private_key_passphrase
        assert private_key_passphrase is not None
        if private_key_filename is None:
            private_key = self.DefaultPrivKey
        else:
            private_key = crypt4gh.keys.get_private_key(
                private_key_filename.as_posix(), lambda: private_key_passphrase_r
            )

        public_keys: "MutableSequence[bytes]" = []
        if public_key_filenames is None or len(public_key_filenames) == 0:
            if private_key_filename is not None:
                raise WorkdirException(
                    "When a custom private key is provided, at least the public key paired with it must also be provided"
                )
            public_keys = [self.DefaultPubKey]
        else:
            for pub_key_filename in public_key_filenames:
                pub_key = crypt4gh.keys.get_public_key(pub_key_filename.as_posix())
                public_keys.append(pub_key)

        encrypt_keys: "MutableSequence[CompoundKey]" = []
        for pub_key in public_keys:
            encrypt_keys.append((0, private_key, pub_key))
        with self.workdir_passphrase_file.open(mode="wb") as encF:
            wplock = RWFileLock(encF)
            with wplock.exclusive_blocking_lock():
                crypt4gh.lib.encrypt(encrypt_keys, clearF, encF, offset=0, span=None)
        del clearF

        return (
            self.DefaultEncfsType,
            self.DefaultEncfsCmd,
            secureWorkdirPassphrase,
            public_keys,
        )

    def _readPassphrase(
        self,
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Tuple[EncryptedFSType, AnyPath, str]":
        """
        This method decrypts a crypt4gh file containing a passphrase
        which has been encrypted with either the WfExS installation
        public key (if the filename is not provided), or the public key
        paired with the provided private key stored in the file.
        """
        clearF = io.BytesIO()
        if private_key_filename is None:
            private_key = self.DefaultPrivKey
        else:
            if private_key_passphrase is None:
                private_key_passphrase_r = ""
            else:
                private_key_passphrase_r = private_key_passphrase
            assert private_key_passphrase is not None
            private_key = crypt4gh.keys.get_private_key(
                private_key_filename, lambda: private_key_passphrase_r
            )

        with self.workdir_passphrase_file.open(mode="rb") as encF:
            rplock = RWFileLock(encF)
            with rplock.shared_blocking_lock():
                crypt4gh.lib.decrypt(
                    [(0, private_key, None)],
                    encF,
                    clearF,
                    offset=0,
                    span=None,
                    sender_pubkey=None,
                )

        encfs_type_str, _, secureWorkdirPassphrase = (
            clearF.getvalue().decode("utf-8").partition("=")
        )
        del clearF

        if secureWorkdirPassphrase == "":
            errmsg = "Encryption filesystem key does not follow the right format"
            self.logger.error(errmsg)
            raise WorkdirException(errmsg)

        try:
            encfs_type = EncryptedFSType(encfs_type_str)
        except:
            errmsg = f"Invalid encryption filesystem {encfs_type_str} in working directory {self.raw_work_dir}"
            raise WorkdirException(errmsg)

        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            errmsg = f"FIXME: Encryption filesystem {encfs_type_str} mount procedure needed by {self.raw_work_dir} is not implemented"
            self.logger.fatal(errmsg)
            raise WorkdirException(errmsg)

        # If the working directory encrypted filesystem does not
        # match the configured one, use its default executable
        encfs_cmd: "AnyPath"
        if encfs_type != self.DefaultEncfsType:
            encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]
        else:
            encfs_cmd = self.DefaultEncfsCmd

        abs_encfs_cmd = shutil.which(encfs_cmd)
        if abs_encfs_cmd is None:
            errmsg = f"FUSE filesystem command {encfs_cmd}, needed by {encfs_type}, used at {self.raw_work_dir}, was not found. Please install it in order to access the encrypted working directory"
            self.logger.fatal(errmsg)
            raise WorkdirException(errmsg)

        return encfs_type, cast("AbsPath", abs_encfs_cmd), secureWorkdirPassphrase

    @staticmethod
    def _wakeupEncDir(
        cond: "threading.Condition", workDir: "pathlib.Path", logger: "logging.Logger"
    ) -> None:
        """
        This method periodically checks whether the directory is still available
        """
        cond.acquire()
        try:
            while not cond.wait(60) and workDir.is_dir():
                pass
        except:
            logger.exception("Wakeup thread failed!")
        finally:
            cond.release()

    def setup(
        self,
        try_secure: "bool",
        paranoid_mode: "bool",
        fail_ok: "bool" = False,
        public_key_filenames: "Optional[Sequence[pathlib.Path]]" = None,
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Tuple[bool, pathlib.Path]":
        if self.work_dir is None:
            uniqueRawWorkDir = self.raw_work_dir
            if self.just_new:
                doSecureWorkDir = try_secure
            else:
                doSecureWorkDir = self.isSecure()

            allowOther = False
            uniqueEncWorkDir: "Optional[pathlib.Path]"
            uniqueWorkDir: "pathlib.Path"
            if doSecureWorkDir:
                # We need to detect whether fuse has enabled user_allow_other
                # the only way I know is parsing /etc/fuse.conf
                if not paranoid_mode and os.path.exists(self.FUSE_SYSTEM_CONF):
                    with open(self.FUSE_SYSTEM_CONF, mode="r") as fsc:
                        for line in fsc:
                            if line.startswith("user_allow_other"):
                                allowOther = True
                                break
                        self.logger.debug(f"FUSE has user_allow_other: {allowOther}")

                uniqueEncWorkDir = uniqueRawWorkDir / ".crypt"
                uniqueWorkDir = uniqueRawWorkDir / "work"

                # This is the passphrase needed to decrypt the filesystem
                used_public_keys: "Sequence[bytes]"
                workdir_passphrase_file_lock = self.workdir_passphrase_file.with_name(
                    self.LOCKFILE_PREFIX + self.workdir_passphrase_file.name
                )
                with workdir_passphrase_file_lock.open(mode="w+b") as wpfL:
                    pplock = RWFileLock(wpfL)
                    with pplock.exclusive_blocking_lock():
                        if self.workdir_passphrase_file.exists():
                            (
                                encfs_type,
                                encfs_cmd,
                                secureWorkdirPassphrase,
                            ) = self._readPassphrase(
                                private_key_filename=private_key_filename,
                                private_key_passphrase=private_key_passphrase,
                            )
                            used_public_keys = []
                        else:
                            # Time to change to an exclusive lock
                            (
                                encfs_type,
                                encfs_cmd,
                                secureWorkdirPassphrase,
                                used_public_keys,
                            ) = self._writePassphrase(
                                private_key_filename=private_key_filename,
                                private_key_passphrase=private_key_passphrase,
                                public_key_filenames=public_key_filenames,
                            )

                self.encfs_type = encfs_type

                # Initially acquire a shared mount lock
                was_setup = False
                was_init = False
                lockfile_mount = self.raw_work_dir / self.LOCKFILE_MOUNT
                self.lmL = lockfile_mount.open(mode="w+b")
                self.lmlock = RWFileLock(self.lmL)

                try:
                    if not uniqueEncWorkDir.exists():
                        self.lmlock.w_blocking_lock()
                    else:
                        self.lmlock.w_lock()
                except LockError:
                    self.lmlock.r_blocking_lock()
                    was_init = True
                    was_setup = True

                # The directories should exist before calling encryption FS mount
                uniqueEncWorkDir.mkdir(parents=True, exist_ok=True)
                uniqueWorkDir.mkdir(parents=True, exist_ok=True)

                # This is needed to avoid shared access
                # Warn/fail earlier
                if os.path.ismount(uniqueWorkDir):
                    # raise WFException("Destination mount point {} is already in use")
                    self.logger.warning(
                        "Destination mount point {} is already in use".format(
                            uniqueWorkDir
                        )
                    )
                    was_setup = True
                elif was_setup:
                    raise WorkdirException(
                        f"Unexpected concurrent state {self.instance_id} {self.nickname}"
                    )
                else:
                    # DANGER!
                    # We are removing leftovers in work directory
                    with os.scandir(uniqueWorkDir) as uwi:
                        for entry in uwi:
                            # Tainted, not empty directory. Moving...
                            if entry.name not in (".", ".."):
                                self.logger.warning(
                                    f"Destination mount point {uniqueWorkDir} is tainted. Moving..."
                                )
                                shutil.move(
                                    uniqueWorkDir.as_posix(),
                                    uniqueWorkDir.with_name(
                                        uniqueWorkDir.name
                                        + "_tainted_"
                                        + str(time.time())
                                    ).as_posix(),
                                )
                                uniqueWorkDir.mkdir(parents=True, exist_ok=True)
                                break

                    # We are going to unmount what we have mounted
                    self.do_unmount = True
                    was_init = True

                    # Now, time to mount the encrypted FS
                    try:
                        ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](
                            pathlib.Path(encfs_cmd),
                            self.EncfsIdleMinutes,
                            uniqueEncWorkDir,
                            uniqueWorkDir,
                            uniqueRawWorkDir,
                            secureWorkdirPassphrase,
                            allowOther,
                        )
                    except Exception as e:
                        errmsg = f"Cannot FUSE mount {uniqueWorkDir} with {encfs_cmd}"
                        self.logger.exception(errmsg)
                        if not fail_ok:
                            raise WorkdirException(errmsg) from e
                        was_setup = False
                    else:
                        # IMPORTANT: There can be a race condition in some containerised
                        # scenarios where the FUSE mount process goes to background, but
                        # mounting itself has not finished. This check helps
                        # both to detect and to avoid that corner case.
                        if not os.path.ismount(uniqueWorkDir):
                            errmsg = f"Corner case: cannot keep mounted FUSE mount {uniqueWorkDir} with {encfs_cmd}"
                            self.logger.exception(errmsg)
                            if not fail_ok:
                                raise WorkdirException(errmsg)
                            was_setup = False

                        was_setup = True
                        # and start the thread which keeps the mount working
                        self.encfsCond = threading.Condition()
                        self.encfsThread = threading.Thread(
                            target=self._wakeupEncDir,
                            args=(self.encfsCond, uniqueWorkDir, self.logger),
                            daemon=True,
                        )
                        self.encfsThread.start()

                        # Time to transfer the public keys
                        # to be used later in the lifecycle
                        if len(used_public_keys) > 0:
                            base_keys_dir = (
                                uniqueWorkDir / WORKDIR_META_RELDIR / "public_keys"
                            )
                            base_keys_dir.mkdir(parents=True, exist_ok=True)
                            key_fns: "MutableSequence[str]" = []
                            manifest = {
                                "creation": datetime.datetime.now().astimezone(),
                                "keys": key_fns,
                            }
                            for i_key, key_fn in enumerate(used_public_keys):
                                dest_fn_basename = f"key_{i_key}.c4gh.public"
                                dest_fn = base_keys_dir / dest_fn_basename
                                with dest_fn.open(mode="wb") as dH:
                                    dH.write(key_fn)
                                key_fns.append(dest_fn_basename)

                            # Last, manifest
                            with (base_keys_dir / "manifest.json").open(
                                mode="wt",
                                encoding="utf-8",
                            ) as mF:
                                json.dump(
                                    manifest, mF, sort_keys=True, cls=DatetimeEncoder
                                )

                # self.encfsPassphrase = secureWorkdirPassphrase
                del secureWorkdirPassphrase
            else:
                uniqueEncWorkDir = None
                uniqueWorkDir = uniqueRawWorkDir
                was_init = True
                was_setup = True

            # The temporary directory is in the raw working directory as
            # some container engine could fail
            uniqueTempDir = uniqueRawWorkDir / ".TEMP"
            uniqueTempDir.mkdir(parents=True, exist_ok=True)
            uniqueTempDir.chmod(0o1777)

            # Setting up working directories, one per instance
            self.enc_work_dir = uniqueEncWorkDir
            self.work_dir = uniqueWorkDir
            self.temp_dir = uniqueTempDir
            self.allow_other = allowOther
            self.was_init = was_init
            self.was_setup = was_setup

        return self.was_setup, self.temp_dir

    def unmount(self) -> None:
        if self.do_unmount and (self.enc_work_dir is not None):
            if self.encfsCond is not None:
                self.encfsCond.acquire()
                self.encfsCond.notify()
                self.encfsThread = None
                self.encfsCond = None
            # Only unmount if it is needed
            if self.lmlock is not None:
                assert self.work_dir is not None
                try:
                    self.lmlock.w_lock()
                    if os.path.ismount(self.work_dir):
                        with tempfile.NamedTemporaryFile() as encfs_umount_stdout, tempfile.NamedTemporaryFile() as encfs_umount_stderr:
                            fusermountCommand: "Sequence[str]" = [
                                self.FusermountCmd,
                                "-u",  # Umount the directory
                                "-z",  # Even if it is not possible to umount it now, hide the mount point
                                self.work_dir.as_posix(),
                            ]

                            retval = subprocess.Popen(
                                fusermountCommand,
                                stdout=encfs_umount_stdout,
                                stderr=encfs_umount_stderr,
                            ).wait()

                            if retval != 0:
                                with open(encfs_umount_stdout.name, mode="r") as c_stF:
                                    encfs_umount_stdout_v = c_stF.read()
                                with open(encfs_umount_stderr.name, mode="r") as c_stF:
                                    encfs_umount_stderr_v = c_stF.read()

                                errstr = "Could not umount {} (retval {})\nCommand: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                                    self.encfs_type,
                                    retval,
                                    " ".join(fusermountCommand),
                                    encfs_umount_stdout_v,
                                    encfs_umount_stderr_v,
                                )
                                raise WorkdirException(errstr)
                except LockError:
                    self.logger.warning(
                        f"Other processes have a lock on the mount, skipping"
                    )
                finally:
                    if self.lmL is not None:
                        self.lmL.close()
                        self.lmL = None
                    self.lmlock = None
            else:
                self.logger.warning(f"Internal lock is not available")

            # This is needed to avoid double work
            self.do_unmount = False
            self.enc_work_dir = None
            self.work_dir = None

    def destroy(self) -> None:
        self.unmount()

        id_json_path = self.raw_work_dir / self.ID_JSON_FILENAME
        id_json_path_lock = id_json_path.with_name(
            self.LOCKFILE_PREFIX + id_json_path.name
        )
        # Acquiring the lock
        with id_json_path_lock.open(mode="w+b") as idL:
            wlock = RWFileLock(idL)
            with wlock.exclusive_lock():
                try:
                    os.unlink(id_json_path)
                except:
                    self.logger.exception(
                        f"Exception while removing {self.ID_JSON_FILENAME} from {self.instance_id} {self.nickname}"
                    )
            shutil.rmtree(self.raw_work_dir, ignore_errors=True)
