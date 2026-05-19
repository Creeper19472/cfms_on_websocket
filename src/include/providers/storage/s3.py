__all__ = ["S3StorageProvider", "S3FileObject"]

from types import TracebackType
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from include.providers.base import FileObject, StorageProvider


class S3FileObject(FileObject):
    def __init__(self, body: StreamingBody):
        self._file = body

    def read(self, size: int = -1) -> bytes:
        return self._file.read(size)

    def write(self, data: bytes) -> int:
        raise NotImplementedError

    def close(self) -> None:
        self._file.close()

    def seekable(self) -> bool:
        return self._file.seekable()

    def seek(self, offset: int, whence: int = 0, /) -> int:
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        return self._file.tell()

    def truncate(self, size: Any = None, /) -> int:
        return self._file.truncate(size)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        self._file.close()


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

    def fopen(self, path: str, mode: str = "rb") -> S3FileObject:
        response = self._client.get_object(
            Bucket=self._bucket_name, Key=path.lstrip("/")
        )
        return S3FileObject(response["Body"])

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
