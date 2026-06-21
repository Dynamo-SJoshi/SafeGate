from __future__ import annotations

import io
import gzip
import tarfile
import zipfile
from pathlib import Path
import logging

logger = logging.getLogger("safegate-archive-utils")

class ArchiveInfo:
    def __init__(self, filename: str, file_size: int, compress_size: int, is_directory: bool):
        self.filename = filename
        self.file_size = file_size
        self.compress_size = compress_size
        self._is_dir = is_directory

    def is_dir(self) -> bool:
        return self._is_dir

class ArchiveReader:
    def __init__(self, file_path: Path, content_type: str | None = None, filename: str | None = None):
        self.file_path = Path(file_path)
        self.filename = filename or self.file_path.name
        self.content_type = content_type or ""
        self._zip_archive: zipfile.ZipFile | None = None
        self._tar_archive: tarfile.TarFile | None = None
        self._gzip_archive: gzip.GzipFile | None = None
        self._archive_type: str | None = None  # "zip", "tar", "gzip"

        fn_lower = self.filename.lower()
        is_tar = (
            self.content_type == "application/x-tar"
            or fn_lower.endswith(".tar")
        )
        is_gz = (
            self.content_type == "application/gzip"
            or fn_lower.endswith((".gz", ".tgz"))
        )

        if is_tar:
            try:
                self._tar_archive = tarfile.open(self.file_path, "r")
                self._archive_type = "tar"
            except Exception as e:
                logger.debug(f"Failed to open as plain tar: {e}")
        elif is_gz:
            if fn_lower.endswith((".tar.gz", ".tgz")):
                try:
                    self._tar_archive = tarfile.open(self.file_path, "r:gz")
                    self._archive_type = "tar"
                except Exception as e:
                    logger.debug(f"Failed to open as tar.gz: {e}")
            if not self._tar_archive:
                try:
                    self._gzip_archive = gzip.open(self.file_path, "rb")
                    self._archive_type = "gzip"
                except Exception as e:
                    logger.debug(f"Failed to open as plain gzip: {e}")

        # Default fallback to ZIP
        if not self._archive_type:
            try:
                self._zip_archive = zipfile.ZipFile(self.file_path)
                self._archive_type = "zip"
            except Exception as e1:
                # Try tar as last resort
                try:
                    self._tar_archive = tarfile.open(self.file_path, "r")
                    self._archive_type = "tar"
                except Exception as e2:
                    logger.error(f"Failed to identify archive structure (ZIP err: {e1}, TAR err: {e2})")
                    raise ValueError("Unsupported or invalid archive format")

    def __enter__(self) -> ArchiveReader:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._zip_archive:
            self._zip_archive.close()
        if self._tar_archive:
            self._tar_archive.close()
        if self._gzip_archive:
            self._gzip_archive.close()

    def namelist(self) -> list[str]:
        if self._archive_type == "zip":
            assert self._zip_archive is not None
            return self._zip_archive.namelist()
        elif self._archive_type == "tar":
            assert self._tar_archive is not None
            return self._tar_archive.getnames()
        elif self._archive_type == "gzip":
            # Determine name of the file inside gzip
            gz_name = None
            try:
                if hasattr(self._gzip_archive, "orig_filename") and self._gzip_archive.orig_filename:
                    gz_name = self._gzip_archive.orig_filename
            except Exception as e:
                logger.debug(f"Failed to extract orig_filename from gzip: {e}")
            
            if not gz_name:
                base_name = Path(self.filename).name
                if base_name.lower().endswith(".gz"):
                    gz_name = base_name[:-3]
                else:
                    gz_name = base_name + ".extracted"
            return [gz_name]
        return []

    def getinfo(self, name: str) -> ArchiveInfo:
        if self._archive_type == "zip":
            assert self._zip_archive is not None
            info = self._zip_archive.getinfo(name)
            return ArchiveInfo(
                filename=info.filename,
                file_size=info.file_size,
                compress_size=info.compress_size,
                is_directory=info.is_dir(),
            )
        elif self._archive_type == "tar":
            assert self._tar_archive is not None
            member = self._tar_archive.getmember(name)
            return ArchiveInfo(
                filename=member.name,
                file_size=member.size,
                compress_size=member.size,
                is_directory=member.isdir(),
            )
        elif self._archive_type == "gzip":
            comp_size = self.file_path.stat().st_size
            size = comp_size
            try:
                with open(self.file_path, "rb") as f:
                    f.seek(-4, 2)
                    size = int.from_bytes(f.read(4), byteorder="little")
            except Exception:
                pass
            return ArchiveInfo(
                filename=name,
                file_size=size,
                compress_size=comp_size,
                is_directory=False,
            )
        raise KeyError(f"File {name} not found in archive")

    def open(self, name: str) -> io.BufferedReader | io.BytesIO | zipfile.ZipExtFile:
        if self._archive_type == "zip":
            assert self._zip_archive is not None
            return self._zip_archive.open(name)
        elif self._archive_type == "tar":
            assert self._tar_archive is not None
            fileobj = self._tar_archive.extractfile(name)
            if fileobj is None:
                raise KeyError(f"Cannot open directory or special file: {name}")
            return fileobj
        elif self._archive_type == "gzip":
            assert self._gzip_archive is not None
            try:
                self._gzip_archive.seek(0)
            except Exception:
                pass
            return self._gzip_archive
        raise KeyError(f"File {name} not found in archive")
