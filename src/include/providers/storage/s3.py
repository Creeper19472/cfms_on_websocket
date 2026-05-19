__all__ = ["S3StorageProvider", "S3FileObject"]

from types import TracebackType
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from include.providers.base import FileObject, StorageProvider


class S3FileObject(FileObject):
    def __init__(self, client, bucket_name: str, key: str, mode: str = "rb"):
        self._client = client
        self._bucket_name = bucket_name
        self._key = key
        self._mode = mode
        self._closed = False

        if "w" in mode:
            self._upload_id = self._client.create_multipart_upload(
                Bucket=self._bucket_name, Key=self._key
            )["UploadId"]
            self._parts = []
            self._buffer = bytearray()
            self._part_number = 1
        else:
            response = self._client.get_object(Bucket=self._bucket_name, Key=self._key)
            self._body: StreamingBody = response["Body"]

    def read(self, size: int = -1) -> bytes:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.read(size)

    def write(self, data: bytes) -> int:
        if "w" not in self._mode:
            raise NotImplementedError
        if self._closed:
            raise ValueError("I/O operation on closed file.")

        self._buffer.extend(data)
        bytes_written = len(data)

        # S3 multipart uploads require parts to be at least 5MB (except the last part)
        while len(self._buffer) >= 5 * 1024 * 1024:
            chunk = self._buffer[: 5 * 1024 * 1024]
            self._buffer = self._buffer[5 * 1024 * 1024 :]
            self._upload_part(chunk)

        return bytes_written

    def _upload_part(self, data: bytes):
        response = self._client.upload_part(
            Bucket=self._bucket_name,
            Key=self._key,
            PartNumber=self._part_number,
            UploadId=self._upload_id,
            Body=bytes(data),
        )
        self._parts.append({"PartNumber": self._part_number, "ETag": response["ETag"]})
        self._part_number += 1

    def close(self) -> None:
        if self._closed:
            return

        if "w" in self._mode:
            if len(self._buffer) > 0 or self._part_number == 1:
                self._upload_part(self._buffer)
                self._buffer.clear()

            self._client.complete_multipart_upload(
                Bucket=self._bucket_name,
                Key=self._key,
                UploadId=self._upload_id,
                MultipartUpload={"Parts": self._parts},
            )
        else:
            self._body.close()

        self._closed = True

    def seekable(self) -> bool:
        if "w" in self._mode:
            return False
        return self._body.seekable()

    def seek(self, offset: int, whence: int = 0, /) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.seek(offset, whence)

    def tell(self) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.tell()

    def truncate(self, size: Any = None, /) -> int:
        if "w" in self._mode:
            raise NotImplementedError
        return self._body.truncate(size)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        if exc_type is not None and "w" in self._mode:
            self._client.abort_multipart_upload(
                Bucket=self._bucket_name,
                Key=self._key,
                UploadId=self._upload_id,
            )
            self._closed = True
            return False

        self.close()


class S3StorageProvider(StorageProvider):
    def __init__(
        self,
        bucket_name: str,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        region_name: str = "us-east-1",
    ):
        self._bucket_name = bucket_name
        self._config = Config(signature_version="s3v4")
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            config=self._config,
            region_name=region_name,
        )

    def fopen(self, path: str, mode: str = "rb") -> FileObject:
        return S3FileObject(
            client=self._client,
            bucket_name=self._bucket_name,
            key=path.lstrip("/"),
            mode=mode,
        )

    def exists(self, path: str) -> bool:
        if path.endswith("/"):
            return True

        try:
            self._client.head_object(Bucket=self._bucket_name, Key=path)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

    def remove(self, path: str) -> bool:
        raise NotImplementedError

    def mkdir(self, path: str, mode: int = 511) -> None:
        raise NotImplementedError

    def makedirs(self, name: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        raise NotImplementedError

    def getsize(self, filename: str, /) -> int:
        raise NotImplementedError
