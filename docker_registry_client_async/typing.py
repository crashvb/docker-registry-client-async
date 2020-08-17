#!/usr/bin/env python

# pylint: disable=missing-class-docstring,too-few-public-methods

"""Typing classes."""

from typing import Any, TypedDict, Union

from aiohttp import ClientResponse

from .formattedsha256 import FormattedSHA256
from .manifest import Manifest


class _AioHttpClientResponse(TypedDict):
    client_response: ClientResponse


class _DockerContentDigest(TypedDict):
    digest: Union[FormattedSHA256, None]


class DockerRegistryClientAsyncResult(_AioHttpClientResponse):
    result: bool


class DockerRegistryClientAsyncGetBlob(_AioHttpClientResponse):
    blob: bytes


class DockerRegistryClientAsyncGetBlobUpload(_AioHttpClientResponse):
    location: str
    range: str


class DockerRegistryClientAsyncGetCatalog(_AioHttpClientResponse):
    catalog: Any


class DockerRegistryClientAsyncGetManifest(_AioHttpClientResponse):
    manifest: Manifest


class DockerRegistryClientAsyncGetTags(_AioHttpClientResponse):
    tags: Any


class DockerRegistryClientAsyncHeadBlob(
    DockerRegistryClientAsyncResult, _DockerContentDigest
):
    pass


class DockerRegistryClientAsyncHeadManifest(
    DockerRegistryClientAsyncResult, _DockerContentDigest
):
    pass


class DockerRegistryClientAsyncXBlobUpload(_AioHttpClientResponse):
    docker_upload_uuid: Union[str, None]
    location: str
    range: str


class DockerRegistryClientAsyncPatchBlobUploadFromDisk(
    DockerRegistryClientAsyncXBlobUpload, _DockerContentDigest
):
    pass


class DockerRegistryClientAsyncPutBlobUpload(
    _AioHttpClientResponse, _DockerContentDigest
):
    # content_range: str
    location: str


class DockerRegistryClientAsyncPutManifest(
    _AioHttpClientResponse, _DockerContentDigest
):
    pass


class ImageNamePareString(TypedDict):
    digest: Union[FormattedSHA256, None]
    endpoint: Union[str, None]
    image: str
    tag: Union[str, None]


class UtilsChunkToFile(_AioHttpClientResponse):
    digest: FormattedSHA256
    size: int
