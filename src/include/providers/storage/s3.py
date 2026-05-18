import hashlib
import os
import tempfile
from contextlib import contextmanager
from typing import BinaryIO, ContextManager

import boto3
import botocore.client
from loguru import logger

from include.providers.base import FileObject, StorageProvider


class S3FileObject(FileObject):
    def __init__(self, s3_client, bucket: str, object_key: str, mode: str):
        self.s3_client = s3_client
        self.bucket = bucket
        self.object_key = object_key
        self.mode = mode
        self.temp_path = None
        self.file_obj = None

    def __enter__(self) -> "S3FileObject":
        if "r" in self.mode:
            # Download the file to a temporary location for reading
            fd, self.temp_path = tempfile.mkstemp()
            os.close(fd)
            try:
                self.s3_client.download_file(
                    self.bucket, self.object_key, self.temp_path
                )
                self.file_obj = open(self.temp_path, "rb")
            except Exception as e:
                if os.path.exists(self.temp_path):
                    os.remove(self.temp_path)
                raise FileNotFoundError(f"S3 get failed: {e}")
        elif "w" in self.mode:
            # For writing, we will buffer writes and upload on close
            self.file_obj = S3BufferedWriter(
                self.s3_client, self.bucket, self.object_key
            )
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
        return self

    def read(self, size: int = -1) -> bytes:
        if not self.file_obj or not hasattr(self.file_obj, "read"):
            raise IOError("File not open for reading")
        return self.file_obj.read(size)

    def write(self, data: bytes) -> int:
        if not self.file_obj or not hasattr(self.file_obj, "write"):
            raise IOError("File not open for writing")
        return self.file_obj.write(data)

    def close(self) -> None:
        if self.file_obj:
            self.file_obj.close()
            if isinstance(self.file_obj, S3BufferedWriter):
                # S3BufferedWriter handles its own cleanup
                pass
            elif os.path.exists(self.temp_path):
                os.remove(self.temp_path)

    def seekable(self) -> bool:
        return hasattr(self.file_obj, "seekable") and self.file_obj.seekable()

    def seek(self, offset: int, whence: int = 0) -> int:
        if not hasattr(self.file_obj, "seek"):
            raise IOError("File does not support seeking")
        return self.file_obj.seek(offset, whence)

    def tell(self) -> int:
        if not hasattr(self.file_obj, "tell"):
            raise IOError("File does not support tell")
        return self.file_obj.tell()


class S3BufferedWriter:
    def __init__(self, s3_client, bucket: str, object_key: str):
        self.s3_client = s3_client
        self.bucket = bucket
        self.object_key = object_key
        # We buffer chunks in a temporary file to avoid keeping large files in memory
        fd, self.temp_path = tempfile.mkstemp()
        self.temp_file = os.fdopen(fd, "wb")

    def write(self, data: bytes):
        self.temp_file.write(data)

    def truncate(self, size: int):
        self.temp_file.truncate(size)

    def close(self):
        self.temp_file.close()
        # Upload the temporary file to S3
        try:
            self.s3_client.upload_file(self.temp_path, self.bucket, self.object_key)
        except Exception as e:
            logger.error(f"Failed to upload to S3: {e}")
            raise
        finally:
            # Clean up the temporary file
            if os.path.exists(self.temp_path):
                os.remove(self.temp_path)


class S3BufferedReader:
    def __init__(self, temp_path: str):
        self.temp_path = temp_path
        self.temp_file = open(temp_path, "rb")

    def read(self, size: int = -1) -> bytes:
        return self.temp_file.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.temp_file.seek(offset, whence)

    def close(self):
        self.temp_file.close()
        if os.path.exists(self.temp_path):
            os.remove(self.temp_path)


class S3StorageProvider(StorageProvider):
    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket_name: str,
        region_name: str,
        secure: bool,
    ):

        config = botocore.client.Config(signature_version="s3v4")
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name,
            config=config,
            use_ssl=secure,
        )
        self.bucket = bucket_name

        # Ensure bucket exists
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except Exception:
            try:
                if region_name == "us-east-1":
                    self.s3.create_bucket(Bucket=self.bucket)
                else:
                    self.s3.create_bucket(
                        Bucket=self.bucket,
                        CreateBucketConfiguration={"LocationConstraint": region_name},
                    )
            except Exception as e:
                logger.warning(f"Could not create bucket {self.bucket}: {e}")

    def _get_key(self, path: str) -> str:
        # Normalize local windows path to object key
        return path.replace("\\", "/").lstrip("./").lstrip("/")

    @contextmanager
    def open_read(self, path: str) -> ContextManager[BinaryIO]:
        # For simplicity, download to a temp file and read from it
        # Real HTTP range queries would be better for high-scale,
        # but ConnectionHandler does `seek` then `read`.
        # Downloading whole file might be slow, but this is a scalable MVP.
        key = self._get_key(path)
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        try:
            self.s3.download_file(self.bucket, key, temp_path)
            reader = S3BufferedReader(temp_path)
            yield reader
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise FileNotFoundError(f"S3 get failed: {e}")
        finally:
            # reader cleanup handles temp file removal on close
            pass

    @contextmanager
    def open_write(self, path: str) -> ContextManager[BinaryIO]:
        key = self._get_key(path)
        writer = S3BufferedWriter(self.s3, self.bucket, key)
        try:
            yield writer
        finally:
            writer.close()

    def get_size(self, path: str) -> int:
        key = self._get_key(path)
        try:
            resp = self.s3.head_object(Bucket=self.bucket, Key=key)
            return resp["ContentLength"]
        except Exception:
            raise FileNotFoundError(f"File {path} not found in S3")

    def exists(self, path: str) -> bool:
        key = self._get_key(path)
        try:
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def remove(self, path: str) -> bool:
        key = self._get_key(path)
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def makedirs(self, path: str) -> None:
        # S3 has no directories
        pass

    def calculate_sha256(self, path: str) -> str:
        # Since we use S3, we might have to download the file to hash it,
        # but if we trust S3's ETags (mostly md5 format),
        # unfortunately the app expects SHA256.
        # Temp download and hash:
        key = self._get_key(path)
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        h = hashlib.sha256()
        try:
            self.s3.download_file(self.bucket, key, temp_path)
            with open(temp_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
