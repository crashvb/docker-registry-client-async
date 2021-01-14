#!/usr/bin/env python

# pylint: disable=too-many-lines,too-many-public-methods

"""Asynchronous Docker Registry Client."""

import json
import logging
import os
import re

from http import HTTPStatus
from pathlib import Path
from ssl import create_default_context, SSLContext
from typing import Any, List, Union
from urllib.parse import urlparse

import aiofiles
import www_authenticate

from aiohttp import (
    AsyncResolver,
    ClientResponse,
    ClientSession,
    Fingerprint,
    TCPConnector,
)
from aiohttp.typedefs import LooseHeaders

from .formattedsha256 import FormattedSHA256
from .hashinggenerator import HashingGenerator
from .imagename import ImageName
from .manifest import Manifest
from .specs import (
    DockerAuthentication,
    DockerMediaTypes,
    MediaTypes,
    OCIMediaTypes,
)
from .typing import (
    DockerRegistryClientAsyncResult,
    DockerRegistryClientAsyncGetBlob,
    DockerRegistryClientAsyncGetBlobUpload,
    DockerRegistryClientAsyncGetCatalog,
    DockerRegistryClientAsyncGetManifest,
    DockerRegistryClientAsyncGetTags,
    DockerRegistryClientAsyncHeadBlob,
    DockerRegistryClientAsyncHeadManifest,
    DockerRegistryClientAsyncXBlobUpload,
    DockerRegistryClientAsyncPatchBlobUploadFromDisk,
    DockerRegistryClientAsyncPutBlobUpload,
    DockerRegistryClientAsyncPutManifest,
    UtilsChunkToFile,
)
from .utils import chunk_to_file, must_be_equal

LOGGER = logging.getLogger(__name__)


class DockerRegistryClientAsync:
    """
    AIOHTTP based Python REST client for the Docker Registry.
    """

    DEFAULT_CREDENTIALS_STORE = Path.home().joinpath(".docker/config.json")
    # TODO: Remove TOKEN_BASED url checks, and implement proper response code parsing, and token lifecycle ...
    DEFAULT_TOKEN_BASED_ENDPOINTS = "index.docker.io,quay.io,registry.redhat.io"
    DEFAULT_PROTOCOL = os.environ.get("DRCA_DEFAULT_PROTOCOL", "https")

    def __init__(
        self,
        *,
        credentials_store: Path = None,
        ssl: Union[None, bool, Fingerprint, SSLContext] = None,
        token_based_endpoints: List[str] = None,
    ):
        """
        Args:
            credentials_store: Path to the docker registry credentials store.
            ssl: SSL context.
            token_based_endpoints: List of token-based endpoints
        """
        if not credentials_store:
            credentials_store = Path(
                os.environ.get(
                    "DRCA_CREDENTIALS_STORE",
                    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE,
                )
            )
        if not ssl:
            cacerts = os.environ.get("DRCA_CACERTS", None)
            if cacerts:
                LOGGER.debug("Using cacerts: %s", cacerts)
                ssl = create_default_context(cafile=str(cacerts))

        if not token_based_endpoints:
            token_based_endpoints = os.environ.get(
                "DRCA_TOKEN_BASED_ENDPOINTS",
                DockerRegistryClientAsync.DEFAULT_TOKEN_BASED_ENDPOINTS,
            ).split(",")

        self.client_session = None
        self.credentials_store = credentials_store
        self.credentials = None
        self.ssl = ssl
        # Endpoint -> scope -> token
        self.tokens = {}
        self.token_based_endpoints = token_based_endpoints

    async def __aenter__(self) -> "DockerRegistryClientAsync":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def add_credentials(self, endpoint: str, credentials: str):
        """
        Assigns registry credentials in memory for a given endpoint.

        Args:
            endpoint: Registry endpoint for which to assign the credentials.
            credentials: The credentials to be assigned
        """
        # Don't shadow self.credentials_store by flagging that credentials have been loaded
        if self.credentials is None:
            await self._load_credentials()
        self.credentials[endpoint] = {"auth": credentials}

    async def close(self):
        """Gracefully closes this instance."""
        if self.client_session:
            await self.client_session.close()

    async def _get_auth_token(
        self, *, credentials: str = None, endpoint: str, scope: str
    ) -> str:
        """
        Retrieves the registry auth token for a given scope.

        Args:
            credentials: The credentials to use to retrieve the auth token.
            endpoint: Registry endpoint for which to retrieve the token.
            scope: The scope of the auth token.

        Returns:
            The corresponding auth token, or None.
        """

        # TODO: Refactor according to: https://docs.docker.com/registry/spec/auth/token/
        if endpoint not in self.tokens:
            self.tokens[endpoint] = {}

        # https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md
        if scope not in self.tokens[endpoint]:
            # Test using HTTP basic authentication to retrieve the www-authenticate response header ...
            headers = {}
            if credentials:
                headers["Authorization"] = f"Basic {credentials}"

            client_session = await self._get_client_session()

            url = f"{DockerRegistryClientAsync.DEFAULT_PROTOCOL}://{endpoint}/v2/"
            client_response = await client_session.get(
                headers=headers, raise_for_status=False, url=url
            )
            auth_params = www_authenticate.parse(
                client_response.headers["Www-Authenticate"]
            )
            bearer = auth_params["bearer"]

            url = DockerAuthentication.DOCKERHUB_URL_PATTERN.format(
                bearer["realm"], bearer["service"], scope
            )
            client_response = await client_session.get(
                headers=headers, raise_for_status=True, url=url
            )
            payload = await client_response.json()

            self.tokens[endpoint][scope] = payload["token"]

        return self.tokens[endpoint][scope]

    async def _get_client_session(self) -> ClientSession:
        """
        Initializes and / or retrieves an AIOHTTP client session.

        Returns:
            The AIOHTTP client session.
        """
        if not self.client_session:
            self.client_session = ClientSession(
                connector=TCPConnector(resolver=AsyncResolver(), ssl=self.ssl)
            )
        return self.client_session

    async def _get_credentials(self, endpoint: str) -> str:
        """
        Retrieves the registry credentials for a given endpoint

        Args:
            endpoint: Registry endpoint for which to retrieve the credentials.

        Returns:
            The corresponding base64 encoded registry credentials, or None.
        """
        result = None

        if self.credentials is None:
            await self._load_credentials()

        for endpoint_auth in [
            u for u in self.credentials if endpoint in (u, urlparse(u).netloc)
        ]:
            result = self.credentials[endpoint_auth].get("auth", None)
            if result:
                break

        return result

    async def _get_request_headers(
        self, image_name: ImageName, headers: LooseHeaders = None, *, scope=None
    ) -> LooseHeaders:
        """
        Generates request headers that contain registry credentials for a given registry endpoint.

        Args:
            image_name: Image name for which to retrieve the request headers.
            headers: Optional supplemental request headers to be returned.
        Keyword Args:
            scope: Optional Scope to use when requesting an authentication token.

        Returns:
            The generated request headers.
        """
        if not headers:
            headers = {}

        if "User-Agent" not in headers:
            # Note: This cannot be imported above, as it causes a circular import!
            from . import __version__  # pylint: disable=import-outside-toplevel

            headers["User-Agent"] = f"docker-registry-client-async/{__version__}"

        endpoint = image_name.resolve_endpoint()
        credentials = await self._get_credentials(endpoint)
        if endpoint in self.token_based_endpoints:
            token = await self._get_auth_token(
                credentials=credentials, endpoint=endpoint, scope=scope
            )
            headers["Authorization"] = f"Bearer {token}"
        elif credentials:
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    @staticmethod
    def _get_image_name_from_blob_upload(location: str) -> ImageName:
        """
        Parses and returns the image name from the location returned for a blob upload.

        Args:
            location: The "Location" header returned by various blob upload API endpoints.

        Returns:
            The corresponding image name.
        """
        parts = urlparse(location)
        image = re.search(r".*/v2/(?P<image>.*)/blobs/uploads", parts.path).group(
            "image"
        )
        return ImageName(image, endpoint=parts.netloc)

    async def _load_credentials(self):
        """Retrieves the registry credentials from the docker registry credentials store for a given endpoint."""
        if self.credentials is None:
            self.credentials = {}

        if self.credentials_store:
            LOGGER.debug("Loading credentials from store: %s", self.credentials_store)

            # TODO: Add support for secure providers:
            #       https://docs.docker.com/engine/reference/commandline/login/#credentials-store
            if self.credentials_store.is_file():
                async with aiofiles.open(self.credentials_store, mode="rb") as file:
                    credentials = json.loads(await file.read()).get("auths", {})
                for endpoint in credentials:
                    self.credentials[endpoint] = credentials[endpoint]

    # Docker Registry V2 API methods

    async def _delete_blob(
        self, image_name: ImageName, digest: FormattedSHA256, **kwargs
    ) -> ClientResponse:
        """
        Delete the blob identified by name and digest.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)
        headers = await self._get_request_headers(
            image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/blobs/{digest}"
        client_session = await self._get_client_session()
        return await client_session.delete(headers=headers, url=url, **kwargs)

    async def delete_blob(
        self, image_name: ImageName, digest: FormattedSHA256, **kwargs
    ) -> DockerRegistryClientAsyncResult:
        """
        Delete the blob identified by name and digest.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        client_response = await self._delete_blob(image_name, digest, **kwargs)
        return {
            "client_response": client_response,
            "result": client_response.status == HTTPStatus.ACCEPTED,
        }

    async def _delete_blob_upload(self, location: str, **kwargs) -> ClientResponse:
        """
        Cancel outstanding upload processes, releasing associated resources. If this is not called, the unfinished
        uploads will eventually timeout.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        kwargs.pop("protocol", None)
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location
        )
        headers = await self._get_request_headers(
            image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        return await client_session.delete(headers=headers, url=location, **kwargs)

    async def delete_blob_upload(
        self, location: str, **kwargs
    ) -> DockerRegistryClientAsyncResult:
        """
        Cancel outstanding upload processes, releasing associated resources. If this is not called, the unfinished
        uploads will eventually timeout.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                result: True if the blob was deleted, False otherwise.
        """
        kwargs.pop("protocol", None)
        client_response = await self._delete_blob_upload(location, **kwargs)
        return {
            "client_response": client_response,
            "result": client_response.status == HTTPStatus.NO_CONTENT,
        }

    async def _delete_manifest(self, image_name: ImageName, **kwargs) -> ClientResponse:
        """
        Delete the manifest identified by name and reference. Note that a manifest can only be deleted by digest.

        Args:
            image_name: The image name.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)
        headers = await self._get_request_headers(
            image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = (
            f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/"
            f"{image_name.resolve_digest()}"
        )
        client_session = await self._get_client_session()
        return await client_session.delete(headers=headers, url=url, **kwargs)

    async def delete_manifest(
        self, image_name: ImageName, **kwargs
    ) -> DockerRegistryClientAsyncResult:
        """
        Delete the manifest identified by name and reference. Note that a manifest can only be deleted by digest.

        Args:
            image_name: The image name.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                result: True if the manifest was deleted, False otherwise.
        """
        client_response = await self._delete_manifest(image_name, **kwargs)
        return {
            "client_response": client_response,
            "result": client_response.status == HTTPStatus.ACCEPTED,
        }

    async def _get_blob(
        self,
        image_name: ImageName,
        digest: FormattedSHA256,
        *,
        accept: str = None,
        **kwargs,
    ) -> ClientResponse:
        """
        Retrieve the blob from the registry identified by digest.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/blobs/{digest}"
        if accept is None:
            accept = f"{MediaTypes.APPLICATION_JSON};q=1.0"
        headers = await self._get_request_headers(
            image_name,
            {"Accept": accept, "Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        return await client_session.get(
            headers=headers, url=url, allow_redirects=True, **kwargs
        )

    async def get_blob(
        self,
        image_name: ImageName,
        digest: FormattedSHA256,
        *,
        accept: str = None,
        **kwargs,
    ) -> DockerRegistryClientAsyncGetBlob:
        """
        Retrieve the blob from the registry identified by digest.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                blob: The corresponding blob (bytes).
                client_response: The underlying client response.
        """
        client_response = await self._get_blob(
            image_name, digest, accept=accept, raise_for_status=True, **kwargs
        )
        data = await client_response.read()
        return {"blob": data, "client_response": client_response}

    async def get_blob_to_disk(
        self,
        image_name: ImageName,
        digest: FormattedSHA256,
        file,
        *,
        accept: str = None,
        file_is_async: bool = True,
        **kwargs,
    ) -> UtilsChunkToFile:
        """
        Fetch the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
            file: The file to which to store the image manifest.
            accept: The "Accept" HTTP request header.
            file_is_async: If True, all file IO operations will be awaited.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The digest value of the blob.
                size: The byte size of the blob.
        """
        client_response = await self._get_blob(
            image_name, digest, accept=accept, raise_for_status=True, **kwargs
        )
        return await chunk_to_file(client_response, file, file_is_async=file_is_async)

    async def _get_blob_upload(self, location: str, **kwargs) -> ClientResponse:
        """
        Retrieve status of upload identified by uuid.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.

        Returns:
            The underlying client response.
        """
        kwargs.pop("protocol", None)
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location
        )
        headers = await self._get_request_headers(
            image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        return await client_session.get(headers=headers, url=location, **kwargs)

    async def get_blob_upload(
        self, location: str, **kwargs
    ) -> DockerRegistryClientAsyncGetBlobUpload:
        """
        Retrieve status of upload identified by uuid.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.

        Returns:
            dict:
                client_response: The underlying client response.
                range: Range indicating the current progress of the upload.
        """
        client_response = await self._get_blob_upload(location, **kwargs)
        return {
            "client_response": client_response,
            "location": client_response.headers["Location"],
            "range": client_response.headers["Range"],
        }

    async def _get_catalog(self, image_name: ImageName, **kwargs) -> ClientResponse:
        """
        List a set of available repositories in the local registry cluster.

        Args:
            image_name: The image name.
        Keyword Args:
            last: Result set will include values lexically after last.
            n: Limit the number of entries in each response. It not present, all entries will be returned.
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        params = {}
        for param in ["last", "n"]:
            if param in kwargs:
                params[param] = kwargs.pop(param)
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Accept": MediaTypes.APPLICATION_JSON},
            scope=DockerAuthentication.SCOPE_REGISTRY_CATALOG,
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/_catalog"
        client_session = await self._get_client_session()
        return await client_session.get(
            headers=headers, params=params, url=url, **kwargs
        )

    async def get_catalog(
        self, image_name: ImageName, **kwargs
    ) -> DockerRegistryClientAsyncGetCatalog:
        """
        List a set of available repositories in the local registry cluster.

        Args:
            image_name: The image name.
        Keyword Args:
            last: Result set will include values lexically after last.
            n: Limit the number of entries in each response. It not present, all entries will be returned.
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                catalog: The corresponding image catalog.
                client_response: The underlying client response.
        """
        client_response = await self._get_catalog(
            image_name, raise_for_status=True, **kwargs
        )
        catalog = await client_response.json()
        return {"catalog": catalog, "client_response": client_response}

    async def _get_manifest(
        self, image_name: ImageName, *, accept: str = None, **kwargs
    ) -> ClientResponse:
        """
        Fetch the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        if image_name.digest:
            identifier = image_name.resolve_digest()
        else:
            identifier = image_name.resolve_tag()
        if accept is None:
            accept = (
                f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V2};q=1.0,{OCIMediaTypes.IMAGE_MANIFEST_V1};q=0.5,"
                f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V1};q=0.1"
            )
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Accept": accept},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        return await client_session.get(headers=headers, url=url, **kwargs)

    async def get_manifest(
        self, image_name: ImageName, *, accept: str = None, **kwargs
    ) -> DockerRegistryClientAsyncGetManifest:
        """
        Fetch the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                manifest: The corresponding Manifest.
        """
        client_response = await self._get_manifest(
            image_name, accept=accept, raise_for_status=True, **kwargs
        )
        data = await client_response.read()
        return {"client_response": client_response, "manifest": Manifest(data)}

    async def get_manifest_to_disk(
        self,
        image_name: ImageName,
        file,
        *,
        accept: str = None,
        file_is_async: bool = True,
        **kwargs,
    ) -> UtilsChunkToFile:
        """
        Fetch the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            file: The file to which to store the image manifest.
            accept: The "Accept" HTTP request header.
            file_is_async: If True, all file IO operations will be awaited.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The digest value of the manifest.
                size: The byte size of the manifest.
        """
        client_response = await self._get_manifest(
            image_name, accept=accept, raise_for_status=True, **kwargs
        )
        return await chunk_to_file(client_response, file, file_is_async=file_is_async)

    async def _get_tags(self, image_name: ImageName, **kwargs) -> ClientResponse:
        """
        Fetch the tags under the repository identified by name.

        Args:
            image_name: The image name.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Accept": MediaTypes.APPLICATION_JSON},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/tags/list"
        client_session = await self._get_client_session()
        return await client_session.get(headers=headers, url=url, **kwargs)

    async def get_tag_list(
        self, image_name: ImageName, **kwargs
    ) -> DockerRegistryClientAsyncGetTags:
        """
        Fetch the tags under the repository identified by name.

        Args:
            image_name: The image name.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                tags: The corresponding list of image tags.
        """
        client_response = await self._get_tags(
            image_name, raise_for_status=True, **kwargs
        )
        tags = await client_response.json()
        tags = [
            ImageName(image_name.image, endpoint=image_name.endpoint, tag=tag)
            for tag in tags["tags"]
        ]
        return {"client_response": client_response, "tags": tags}

    async def get_tags(
        self, image_name: ImageName, **kwargs
    ) -> DockerRegistryClientAsyncGetTags:
        """
        Fetch the tags under the repository identified by name.

        Args:
            image_name: The image name.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                tags: The corresponding list of image tags.
        """
        client_response = await self._get_tags(
            image_name, raise_for_status=True, **kwargs
        )
        tags = await client_response.json()
        return {"client_response": client_response, "tags": tags}

    async def _get_version(
        self, image_name: ImageName, *, version: str = "2", **kwargs
    ) -> ClientResponse:
        """
        Check that the endpoint implements Docker Registry API V2.

        Args:
            image_name: The image name from which to extract the endpoint.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Content-Type": MediaTypes.APPLICATION_JSON},
            scope=DockerAuthentication.SCOPE_REGISTRY_CATALOG,
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v{version}/"
        client_session = await self._get_client_session()
        return await client_session.head(headers=headers, url=url, **kwargs)

    async def get_version(
        self, image_name: ImageName, **kwargs
    ) -> DockerRegistryClientAsyncResult:
        """
        Check that the endpoint implements Docker Registry API V2.

        Args:
            image_name: The image name from which to extract the endpoint.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                result: True if the v2 API is implemented, False otherwise
        """
        client_response = await self._get_version(image_name, **kwargs)
        return {
            "client_response": client_response,
            "result": client_response.status == HTTPStatus.OK,
        }

    async def _head_blob(
        self, image_name: ImageName, digest: FormattedSHA256, **kwargs
    ) -> ClientResponse:
        """
        Check a blob for existence.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/blobs/{digest}"
        headers = await self._get_request_headers(
            image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        return await client_session.head(
            headers=headers, url=url, allow_redirects=True, **kwargs
        )

    async def head_blob(
        self, image_name: ImageName, digest: FormattedSHA256, **kwargs
    ) -> DockerRegistryClientAsyncHeadBlob:
        """
        Check a blob for existence.

        Args:
            image_name: The image name.
            digest: Digest of the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The blob digest returned by the server, or None.
                result: True if the blob exists, False otherwise.
        """
        client_response = await self._head_blob(image_name, digest, **kwargs)
        digest = None
        if "Docker-Content-Digest" in client_response.headers:
            digest = FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            )
        return {
            "client_response": client_response,
            "digest": digest,
            "result": client_response.status == HTTPStatus.OK,
        }

    async def _head_manifest(
        self, image_name: ImageName, *, accept: str = None, **kwargs
    ) -> ClientResponse:
        """
        Check an image manifest for existence.

        Args:
            image_name: The image name.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        if image_name.digest:
            identifier = image_name.resolve_digest()
        else:
            identifier = image_name.resolve_tag()
        if accept is None:
            accept = (
                f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V2};q=1.0,{OCIMediaTypes.IMAGE_MANIFEST_V1};q=0.5,"
                f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V1};q=0.1"
            )
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Accept": accept},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        return await client_session.head(headers=headers, url=url, **kwargs)

    async def head_manifest(
        self, image_name: ImageName, *, accept: str = None, **kwargs
    ) -> DockerRegistryClientAsyncHeadManifest:
        """
        Check an image manifest for existence.

        Args:
            image_name: The image name.
            accept: The "Accept" HTTP request header.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The manifest digest returned by the server, or None.
                result: True if the image manifest exists, False otherwise.
        """
        client_response = await self._head_manifest(image_name, accept=accept, **kwargs)
        digest = None
        if "Docker-Content-Digest" in client_response.headers:
            digest = FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            )
        return {
            "client_response": client_response,
            "digest": digest,
            "result": client_response.status == HTTPStatus.OK,
        }

    async def _patch_blob_upload(
        self, location: str, data: Union[bytes, Any], *, offset: int = None, **kwargs
    ) -> ClientResponse:
        """
        Upload a chunk of data for the specified upload.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            data: Binary data.
            offset:
                Range of bytes identifying the desired block of content represented by the body. This parameter should
                provided for chunked uploads, and omitted for stream uploads.

        Returns:
            The underlying client response.
        """
        kwargs.pop("protocol", None)
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location
        )
        headers = await self._get_request_headers(
            image_name,
            {"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        if offset is not None:
            headers["Content-Range"] = f"{offset}-{offset + len(data) - 1}"
        client_session = await self._get_client_session()
        return await client_session.patch(
            headers=headers, data=data, url=location, **kwargs
        )

    async def patch_blob_upload(
        self, location: str, data: bytes, *, offset: int = None, **kwargs
    ) -> DockerRegistryClientAsyncXBlobUpload:
        """
        Upload a chunk of data for the specified upload.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            data: Binary data.
            offset:
                Range of bytes identifying the desired block of content represented by the body. This parameter should
                provided for chunked uploads, and omitted for stream uploads.

        Returns:
            client_response: The underlying client response.
            docker_upload_uuid: Identifies the docker upload uuid for the current request.
            location:
                The location of the upload. Clients should assume this changes after each request. Clients should use
                the contents verbatim to complete the upload, adding parameters where required.
            range:
                Range header indicating the progress of the upload.
        """
        client_response = await self._patch_blob_upload(
            location, data, offset=offset, raise_for_status=True, **kwargs
        )
        return {
            "client_response": client_response,
            "docker_upload_uuid": client_response.headers["Docker-Upload-UUID"],
            "location": client_response.headers["Location"],
            "range": client_response.headers["Range"],
        }

    async def patch_blob_upload_from_disk(
        self, location: str, file, *, file_is_async: bool = True, **kwargs
    ) -> DockerRegistryClientAsyncPatchBlobUploadFromDisk:
        """
        Upload a chunk of data for the specified upload.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            file: The file to which to store the image manifest.
            file_is_async: If True, all file IO operations will be awaited

        Returns:
            client_response: The underlying client response.
            digest: The digest of the local content.
            docker_upload_uuid: Identifies the docker upload uuid for the current request.
            location:
                The location of the upload. Clients should assume this changes after each request. Clients should use
                the contents verbatim to complete the upload, adding parameters where required.
            range:
                Range header indicating the progress of the upload.
        """
        hashing_generator = HashingGenerator(file, file_is_async=file_is_async)
        client_response = await self._patch_blob_upload(
            location,
            hashing_generator,
            raise_for_status=True,
            **kwargs,
        )
        return {
            "client_response": client_response,
            "digest": hashing_generator.get_digest(),
            "docker_upload_uuid": client_response.headers["Docker-Upload-UUID"],
            "location": client_response.headers["Location"],
            "range": client_response.headers["Range"],
        }

    async def _post_blob(
        self,
        image_name: ImageName,
        *,
        data: bytes = None,
        digest: FormattedSHA256 = None,
        source: ImageName = None,
        **kwargs,
    ) -> ClientResponse:
        """
        Initiate a resumable blob upload. If successful, an upload location will be provided to complete the upload.
        Optionally, if the digest parameter is present, the request body will be used to complete the upload in a single
        request.

        Args:
            image_name: The image name.
            data: Binary data.
            digest:
                For monolithic uploads the digest of the blob; for blob mounting, the digest value of the blob in the
                source repository to be mounted.
            source: The image name of the source repository from which to mount the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/blobs/uploads/"
        headers = await self._get_request_headers(
            image_name,
            {"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        params = {}
        if digest and source:
            # TODO: 'library/' image prefix does not work with mounting (on DockerHub) ...
            # params["from"] = re.sub(r"^library/", "", source.resolve_image())
            params["from"] = source.resolve_image()
            params["mount"] = digest
        elif digest:
            params["digest"] = digest
        client_session = await self._get_client_session()
        return await client_session.post(
            data=data, headers=headers, params=params, url=url, **kwargs
        )

    async def post_blob(
        self,
        image_name: ImageName,
        *,
        data: bytes = None,
        digest: FormattedSHA256 = None,
        source: ImageName = None,
        **kwargs,
    ) -> DockerRegistryClientAsyncXBlobUpload:
        """
        Initiate a resumable blob upload. If successful, an upload location will be provided to complete the upload.
        Optionally, if the digest parameter is present, the request body will be used to complete the upload in a single
        request.

        Args:
            image_name: The image name.
            data: Binary data.
            digest:
                For monolithic uploads the digest of the blob, for blob mounting, the digest value of the blob in the
                source repository to be mounted.
            source: The image name of the source repository from which to mount the blob.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                docker_upload_uuid: Identifies the docker upload uuid for the current request.
                location:
                    The location of the created upload. Clients should use the contents verbatim to complete the upload,
                    adding parameters where required.
                range:
                    Range header indicating the progress of the upload. When starting an upload, it will return an empty
                    range, since no content has been received.
        """
        client_response = await self._post_blob(
            image_name,
            data=data,
            digest=digest,
            source=source,
            raise_for_status=True,
            **kwargs,
        )
        return {
            "client_response": client_response,
            "docker_upload_uuid": client_response.headers.get(
                "Docker-Upload-UUID", None
            ),
            "location": client_response.headers["Location"],
            "range": client_response.headers["Range"],
        }

    async def _put_blob_upload(
        self,
        location: str,
        digest: FormattedSHA256,
        *,
        data: Union[bytes, Any] = None,
        **kwargs,
    ) -> ClientResponse:
        """
        Complete the upload specified by uuid, optionally appending the body as the final chunk.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            digest: Digest of the (total) blob.
            data: Binary data.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        kwargs.pop("protocol", None)
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location
        )
        headers = await self._get_request_headers(
            image_name,
            {"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        params = {"digest": digest}
        client_session = await self._get_client_session()
        return await client_session.put(
            data=data, headers=headers, params=params, url=location, **kwargs
        )

    async def put_blob_upload(
        self, location: str, digest: FormattedSHA256, *, data: bytes = None, **kwargs
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        """
        Complete the upload specified by uuid, optionally appending the body as the final chunk.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            digest: Digest of the (total) blob.
            data: Binary data.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: Digest of the targeted content for the request.
                location: The canonical location of the blob for retrieval.
        """
        client_response = await self._put_blob_upload(
            location, digest, data=data, raise_for_status=True, **kwargs
        )
        return {
            "client_response": client_response,
            # Bad docs (code check: registry/handlers/blobupload.go:360)
            # "content_range": client_response.headers["Content-Range"],
            "digest": FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            ),
            "location": client_response.headers["Location"],
        }

    async def put_blob_upload_from_disk(
        self,
        location: str,
        digest: FormattedSHA256,
        file,
        *,
        check_digest: bool = True,
        file_is_async: bool = True,
        **kwargs,
    ) -> DockerRegistryClientAsyncPutBlobUpload:
        """
        Complete the upload specified by uuid, appending the body as the final chunk.

        Args:
            location: Valued of the previous location header from which to retrieve the UUID.
            check_digest: If True, an exception will be raised if the local and uploaded digests are inconsistent.
            digest: Digest of the (total) blob.
            file: The file from which to retrieve the image manifest.
            file_is_async: If True, all file IO operations will be awaited.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The manifest digest returned by the server.
                location: The canonical location of the blob for retrieval.
        """
        hashing_generator = HashingGenerator(file, file_is_async=file_is_async)
        client_response = await self._put_blob_upload(
            location,
            digest,
            data=hashing_generator,
            raise_for_status=True,
            **kwargs,
        )
        digest = FormattedSHA256.parse(client_response.headers["Docker-Content-Digest"])
        if check_digest:
            must_be_equal(
                hashing_generator.get_digest(),
                digest,
                "Remote and local digests are inconsistent",
            )
        return {
            "client_response": client_response,
            # Bad docs (code check: registry/handlers/blobupload.go:360)
            # "content_range": client_response.headers["Content-Range"],
            "digest": digest,
            "location": client_response.headers["Location"],
        }

    async def _put_manifest(
        self,
        image_name: ImageName,
        manifest: Union[bytes, Any],
        *,
        media_type: str = MediaTypes.APPLICATION_JSON,
        **kwargs,
    ) -> ClientResponse:
        """
        Put the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            manifest: The image manifest.
            media_type: The media type of the image manifest.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            The underlying client response.
        """
        if image_name.digest:
            identifier = image_name.resolve_digest()
        else:
            identifier = image_name.resolve_tag()
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            image_name,
            {"Content-Type": media_type},
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        return await client_session.put(
            headers=headers, data=manifest, url=url, **kwargs
        )

    async def put_manifest(
        self, image_name: ImageName, manifest: Manifest, **kwargs
    ) -> DockerRegistryClientAsyncPutManifest:
        """
        Put the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            manifest: The image manifest.
            **kwargs: Pass-through.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The manifest digest returned by the server.
        """
        client_response = await self._put_manifest(
            image_name,
            manifest.get_bytes(),
            media_type=manifest.get_media_type(),
            raise_for_status=True,
            **kwargs,
        )
        return {
            "client_response": client_response,
            "digest": FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            ),
        }

    async def put_manifest_from_disk(
        self,
        image_name: ImageName,
        file,
        *,
        check_digest: bool = True,
        file_is_async: bool = True,
        media_type: str = MediaTypes.APPLICATION_JSON,
        **kwargs,
    ) -> DockerRegistryClientAsyncPutManifest:
        """
        Put the manifest identified by name and reference where reference can be a tag or digest.

        Args:
            image_name: The image name.
            check_digest: If True, an exception will be raised if the local and uploaded digests are inconsistent.
            file: The file from which to retrieve the image manifest.
            file_is_async: If True, all file IO operations will be awaited.
            media_type: The media type of the image manifest.
        Keyword Args:
            protocol: Protocol to use when connecting to the endpoint.

        Returns:
            dict:
                client_response: The underlying client response.
                digest: The manifest digest returned by the server.
        """
        hashing_generator = HashingGenerator(file, file_is_async=file_is_async)
        client_response = await self._put_manifest(
            image_name,
            hashing_generator,
            media_type=media_type,
            raise_for_status=True,
            **kwargs,
        )
        digest = FormattedSHA256.parse(client_response.headers["Docker-Content-Digest"])
        if check_digest:
            must_be_equal(
                hashing_generator.get_digest(),
                digest,
                "Remote and local digests are inconsistent",
            )
        return {"client_response": client_response, "digest": digest}
