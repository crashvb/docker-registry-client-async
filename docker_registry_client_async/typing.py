#!/usr/bin/env python

# pylint: disable=missing-class-docstring,too-few-public-methods

"""Typing classes."""

from typing import Any, NamedTuple, Optional

from aiohttp import ClientResponse

from .formattedsha256 import FormattedSHA256
from .manifest import Manifest


class DockerRegistryClientAsyncResult(NamedTuple):
    client_response: ClientResponse
    result: bool


class DockerRegistryClientAsyncGetBlob(NamedTuple):
    client_response: ClientResponse
    blob: bytes


class DockerRegistryClientAsyncGetBlobUpload(NamedTuple):
    client_response: ClientResponse
    location: str
    range: str


class DockerRegistryClientAsyncGetCatalog(NamedTuple):
    client_response: ClientResponse
    catalog: Any


class DockerRegistryClientAsyncGetManifest(NamedTuple):
    client_response: ClientResponse
    manifest: Manifest


class DockerRegistryClientAsyncGetTags(NamedTuple):
    client_response: ClientResponse
    tags: Any


class DockerRegistryClientAsyncHeadBlob(NamedTuple):
    client_response: ClientResponse
    digest: Optional[FormattedSHA256]
    result: bool


class DockerRegistryClientAsyncHeadManifest(NamedTuple):
    client_response: ClientResponse
    digest: Optional[FormattedSHA256]
    result: bool


class DockerRegistryClientAsyncXBlobUpload(NamedTuple):
    client_response: ClientResponse
    docker_upload_uuid: Optional[str]
    location: str
    range: str


class DockerRegistryClientAsyncPatchBlobUploadFromDisk(NamedTuple):
    client_response: ClientResponse
    digest: Optional[FormattedSHA256]
    docker_upload_uuid: Optional[str]
    location: str
    range: str


class DockerRegistryClientAsyncPutBlobUpload(NamedTuple):
    client_response: ClientResponse
    digest: Optional[FormattedSHA256]
    # content_range: str
    location: str


class DockerRegistryClientAsyncPutManifest(NamedTuple):
    client_response: ClientResponse
    digest: Optional[FormattedSHA256]


class ImageNameParseString(NamedTuple):
    digest: Optional[FormattedSHA256]
    endpoint: Optional[str]
    image: str
    tag: Optional[str]


class UtilsChunkToFile(NamedTuple):
    client_response: ClientResponse
    digest: FormattedSHA256
    size: int
