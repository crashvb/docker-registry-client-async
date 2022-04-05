#!/usr/bin/env python

# pylint: disable=too-many-lines,too-many-public-methods

"""Asynchronous Docker Registry Client."""

import json
import logging
import os
import re

from http import HTTPStatus
from pathlib import Path
from re import Pattern
from ssl import create_default_context, SSLContext
from typing import Any, Dict, List, Optional, Union
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
from aiohttp.helpers import BasicAuth
from aiohttp.typedefs import LooseHeaders

from .formattedsha256 import FormattedSHA256
from .hashinggenerator import HashingGenerator
from .imagename import ImageName
from .manifest import Manifest
from .specs import (
    DockerAuthentication,
    DockerMediaTypes,
    GENERIC_OAUTH2_URL_PATTERN,
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
    # pylint: disable=too-many-instance-attributes
    """
    AIOHTTP based Python REST client for the Docker Registry.
    """

    DEBUG = os.environ.get("DRCA_DEBUG", "")
    DEFAULT_CREDENTIALS_STORE = Path.home().joinpath(".docker/config.json")
    DEFAULT_MEDIA_TYPES_BLOB = (
        f"{MediaTypes.APPLICATION_JSON};q=1.0,{MediaTypes.ANY_ANY};0.1"
    )
    DEFAULT_MEDIA_TYPES_MANIFEST = (
        f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V2};q=1.0,"
        f"{OCIMediaTypes.IMAGE_MANIFEST_V1};q=0.9,"
        f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2};q=0.8,"
        f"{OCIMediaTypes.IMAGE_INDEX_V1};q=0.7,"
        f"{MediaTypes.APPLICATION_JSON};q=0.6"
        f"{DockerMediaTypes.DISTRIBUTION_MANIFEST_V1};q=0.5"
    )
    DEFAULT_PROTOCOL = os.environ.get("DRCA_DEFAULT_PROTOCOL", "https")

    def __init__(
        self,
        *,
        client_session: ClientSession = None,
        client_session_kwargs: Dict = None,
        credentials_store: Path = None,
        fallback_basic_auth: bool = True,
        no_proxy: str = None,
        proxies: Dict[str, str] = None,
        proxy_auth: BasicAuth = None,
        resolver_kwargs: Dict = None,
        ssl: Union[None, bool, Fingerprint, SSLContext] = None,
        tcp_connector_kwargs: Dict = None,
        **kwargs,
    ):
        # pylint: disable=too-many-branches,unused-argument
        """
        Args:
            client_session: The underlying client session to use when making connections.
            client_session_kwargs: Arguments to be passed to the client session.
            credentials_store: Path to the docker registry credentials store.
            no_proxy: A comma separated list of domains to exclude from proxying.
            proxies: Mapping of protocols to proxy urls, optionally including credentials.
            proxy_auth: The credentials to use when proxying.
            resolver_kwargs: Arguments to be passed to the resolver
            ssl: SSL context.
            tcp_connector_kwargs: Arguments to be passed to the TCP connector.
            token_based_endpoints: List of token-based endpoints
        """
        if not client_session_kwargs:
            client_session_kwargs = {}
        if not credentials_store:
            credentials_store = Path(
                os.environ.get(
                    "DRCA_CREDENTIALS_STORE",
                    DockerRegistryClientAsync.DEFAULT_CREDENTIALS_STORE,
                )
            )
        if not proxies:
            proxies = {}
        http_proxy = os.environ.get("HTTP_PROXY", os.environ.get("http_proxy"))
        if http_proxy and "http" not in proxies:
            proxies["http"] = http_proxy
        https_proxy = os.environ.get("HTTPS_PROXY", os.environ.get("https_proxy"))
        if https_proxy and "https" not in proxies:
            proxies["https"] = https_proxy
        if not no_proxy:
            no_proxy = os.environ.get("NO_PROXY", os.environ.get("no_proxy"))
        no_proxy = no_proxy.split(",") if no_proxy else []
        if not resolver_kwargs:
            resolver_kwargs = {}
        if not ssl:
            cacerts = os.environ.get("DRCA_CACERTS", None)
            if cacerts:
                if DockerRegistryClientAsync.DEBUG:
                    LOGGER.debug("Using cacerts: %s", cacerts)
                ssl = create_default_context(cafile=str(cacerts))
        if ssl and DockerRegistryClientAsync.DEBUG:
            LOGGER.debug("SSL Context: %s", ssl.cert_store_stats())
        if not tcp_connector_kwargs:
            tcp_connector_kwargs = {}

        self.client_session = client_session
        self.client_session_kwargs = client_session_kwargs
        self.credentials_store = credentials_store
        # Endpoint Pattern -> credentials
        self.credentials = None  # type: Optional[Dict[Pattern, str]]
        self.fallback_basic_auth = fallback_basic_auth
        self.proxies = proxies
        self.proxy_auth = proxy_auth
        self.proxy_no = no_proxy
        self.resolver_kwargs = resolver_kwargs
        self.ssl = ssl
        self.tcp_connector_kwargs = tcp_connector_kwargs
        # Endpoint -> scope -> token
        self.tokens = {}  # type: Dict[Pattern, Dict[str, str]]

    async def __aenter__(self) -> "DockerRegistryClientAsync":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def add_credentials(self, *, credentials: str, endpoint: Union[Pattern, str]):
        """
        Assigns registry credentials in memory for a given endpoint.

        Args:
            credentials: The credentials to be assigned.
            endpoint: Registry endpoint (<hostname>:[<port>]) for which to assign the credentials.
        """
        # Don't shadow self.credentials_store by flagging that credentials have been loaded
        if self.credentials is None:
            await self._load_credentials()
        if not isinstance(endpoint, Pattern):
            endpoint = await DockerRegistryClientAsync._get_endpoint_pattern(
                endpoint=endpoint
            )
        self.credentials[endpoint] = credentials

    async def add_token(self, *, endpoint: Union[Pattern, str], scope: str, token: str):
        """
        Assigns a registry auth token in memory for a given endpoint and scope.

        Args:
            endpoint: Registry endpoint (<hostname>:[<port>]) for which to assign the token.
            scope: Scope of the auth token to be assigned.
            token: The auth token to be assigned.
        """
        if not isinstance(endpoint, Pattern):
            endpoint = await DockerRegistryClientAsync._get_endpoint_pattern(
                endpoint=endpoint
            )
        if endpoint not in self.tokens:
            self.tokens[endpoint] = {}
        self.tokens[endpoint][scope] = token

    async def close(self):
        """Gracefully closes this instance."""
        if self.client_session:
            await self.client_session.close()
        self.client_session = None

    async def _get_auth_token(
        self, *, credentials: str = None, endpoint: str, scope: str
    ) -> Optional[str]:
        """
        Retrieves the registry auth token for a given scope.

        Args:
            credentials: The credentials to use to retrieve the auth token.
            endpoint: Registry endpoint for which to retrieve the token.
            scope: The scope of the auth token.

        Returns:
            The corresponding auth token, or None.
        """
        # https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md
        # Retrieve the www-authenticate response header from the registry endpoint ...
        client_session = await self._get_client_session()

        protocol = DockerRegistryClientAsync.DEFAULT_PROTOCOL
        url = f"{protocol}://{endpoint}/v2/"
        proxy = await self._get_proxy(endpoint=endpoint, protocol=protocol)
        client_response = await client_session.get(
            raise_for_status=False,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
        )
        if (
            client_response.status != 401
            or "Www-Authenticate" not in client_response.headers
        ):
            return None
        auth_params = www_authenticate.parse(
            client_response.headers["Www-Authenticate"]
        )
        # Note: Www-Authenticate can also specify "basic".
        if "bearer" not in auth_params:
            return None
        bearer = auth_params["bearer"]

        # Retrieve the bearer token from the authorization endpoint ...
        headers = {}
        if credentials:
            headers["Authorization"] = f"Basic {credentials}"
        url = GENERIC_OAUTH2_URL_PATTERN.format(
            bearer["realm"], bearer["service"], scope
        )
        client_response = await client_session.get(
            headers=headers,
            raise_for_status=True,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
        )
        payload = await client_response.json()
        return payload.get("token", None)

    async def _get_client_session(self) -> ClientSession:
        """
        Initializes and / or retrieves an AIOHTTP client session.

        Returns:
            The AIOHTTP client session.
        """
        if not self.client_session:
            if "resolver" not in self.tcp_connector_kwargs:
                self.tcp_connector_kwargs["resolver"] = AsyncResolver(
                    **self.resolver_kwargs
                )
            if "ssl" not in self.tcp_connector_kwargs:
                self.tcp_connector_kwargs["ssl"] = self.ssl
            if "connector" not in self.client_session_kwargs:
                self.client_session_kwargs["connector"] = TCPConnector(
                    **self.tcp_connector_kwargs
                )
            self.client_session = ClientSession(**self.client_session_kwargs)

        return self.client_session

    async def _get_credentials(self, *, endpoint: str) -> Optional[str]:
        """
        Retrieves the registry credentials for a given endpoint.

        Args:
            endpoint: Registry endpoint for which to retrieve the credentials.

        Returns:
            The corresponding base64 encoded registry credentials, or None.
        """
        result = None

        if self.credentials is None:
            await self._load_credentials()

        for pattern, credentials in self.credentials.items():
            if pattern.fullmatch(endpoint):
                result = credentials
                break

        return result

    @staticmethod
    async def _get_endpoint_pattern(*, endpoint: str) -> Pattern:
        """Converts a given endpoint to a regular expression pattern that matches the endpoint."""

        # Legacy endpoint formats included the protocol and path segments; convert them to netloc / address ...
        # Note: urlparse handles many edge-cases, but stores 'netloc' in 'path' if not protocol is specified.
        if "://" not in endpoint:
            endpoint = f"proto://{endpoint}"
        endpoint = urlparse(endpoint).netloc
        return re.compile(f"^{re.escape(endpoint)}$")

    async def _get_proxy(self, *, endpoint: str, protocol: str) -> Optional[str]:
        """
        Retrieves the proxy configuration for a given endpoint.

        Args:
            endpoint: The endpoint for which to retrieve the proxy configuration.
        """
        result = None
        if endpoint not in self.proxy_no and protocol in self.proxies:
            result = self.proxies[protocol]
        return result

    async def _get_request_headers(
        self, *, image_name: ImageName, headers: LooseHeaders = None, scope=None
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
        credentials = await self._get_credentials(endpoint=endpoint)
        token = await self._get_token(
            credentials=credentials, endpoint=endpoint, scope=scope
        )
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif self.fallback_basic_auth and credentials:
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    @staticmethod
    def _get_image_name_from_blob_upload(*, location: str) -> ImageName:
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

    @staticmethod
    def _get_protocol_from_blob_upload(*, location: str) -> str:
        """
        Parses and returns the protocol from the location returned for a blob upload

        Args:
            location: The "Location" header returned by various blob upload API endpoints.

        Returns:
            The corresponding protocol.
        """
        return location.split("://")[0].lower()

    async def _get_token(
        self, *, credentials: str = None, endpoint: str, scope: str
    ) -> Optional[str]:
        """
        Retrieves the registry auth token for a given endpoint.

        Args:
            credentials: The credentials to use to retrieve the auth token.
            endpoint: Registry endpoint for which to retrieve the token.
            scope: The scope of the auth token.

        Returns:
            The corresponding registry auth token, or None.
        """
        # TODO: Implement proper token lifecycle ...
        key = None
        for pattern in self.tokens:
            if pattern.fullmatch(endpoint):
                key = pattern
                break
        if key is None:
            key = await DockerRegistryClientAsync._get_endpoint_pattern(
                endpoint=endpoint
            )
        if scope not in self.tokens.get(key, {}):
            token = await self._get_auth_token(
                credentials=credentials, endpoint=endpoint, scope=scope
            )
            await self.add_token(endpoint=key, scope=scope, token=token)

        return self.tokens[key][scope]

    async def _load_credentials(self):
        """Retrieves the registry credentials from the docker registry credentials store."""
        if self.credentials is None:
            self.credentials = {}

        if self.credentials_store:
            if DockerRegistryClientAsync.DEBUG:
                LOGGER.debug(
                    "Loading credentials from store: %s", self.credentials_store
                )

            # TODO: Add support for secure providers:
            #       https://docs.docker.com/engine/reference/commandline/login/#credentials-store
            if self.credentials_store.is_file():
                async with aiofiles.open(self.credentials_store, mode="rb") as file:
                    credentials = json.loads(await file.read()).get("auths", {})
                for endpoint, auth in credentials.items():
                    endpoint = await DockerRegistryClientAsync._get_endpoint_pattern(
                        endpoint=endpoint
                    )
                    await self.add_credentials(
                        endpoint=endpoint, credentials=auth["auth"]
                    )

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
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/blobs/{digest}"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.delete(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncResult(
            client_response=client_response,
            result=(client_response.status == HTTPStatus.ACCEPTED),
        )

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
        protocol = DockerRegistryClientAsync._get_protocol_from_blob_upload(
            location=location
        )
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location=location
        )
        headers = await self._get_request_headers(
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.delete(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            url=location,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncResult(
            client_response=client_response,
            result=(client_response.status == HTTPStatus.NO_CONTENT),
        )

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
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = (
            f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/"
            f"{image_name.resolve_digest()}"
        )
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.delete(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncResult(
            client_response=client_response,
            result=(client_response.status == HTTPStatus.ACCEPTED),
        )

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
            accept = DockerRegistryClientAsync.DEFAULT_MEDIA_TYPES_BLOB
        headers = await self._get_request_headers(
            headers={
                "Accept": accept,
                "Content-Type": MediaTypes.APPLICATION_OCTET_STREAM,
            },
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.get(
            allow_redirects=True,
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
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
        return DockerRegistryClientAsyncGetBlob(
            blob=data, client_response=client_response
        )

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
        protocol = DockerRegistryClientAsync._get_protocol_from_blob_upload(
            location=location
        )
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location=location
        )
        headers = await self._get_request_headers(
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.get(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            url=location,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncGetBlobUpload(
            client_response=client_response,
            location=client_response.headers["Location"],
            range=client_response.headers["Range"],
        )

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
            headers={"Accept": MediaTypes.APPLICATION_JSON},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REGISTRY_CATALOG,
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/_catalog"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.get(
            headers=headers,
            params=params,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
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
        return DockerRegistryClientAsyncGetCatalog(
            catalog=catalog, client_response=client_response
        )

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
            accept = DockerRegistryClientAsync.DEFAULT_MEDIA_TYPES_MANIFEST
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            headers={"Accept": accept},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.get(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncGetManifest(
            client_response=client_response, manifest=Manifest(data)
        )

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
        params = {}
        for param in ["last", "n"]:
            if param in kwargs:
                params[param] = kwargs.pop(param)
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            headers={"Accept": MediaTypes.APPLICATION_JSON},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/tags/list"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.get(
            headers=headers,
            params=params,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncGetTags(
            client_response=client_response, tags=tags
        )

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
        return DockerRegistryClientAsyncGetTags(
            client_response=client_response, tags=tags
        )

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
            headers={"Content-Type": MediaTypes.APPLICATION_JSON},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REGISTRY_CATALOG,
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v{version}/"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.head(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncResult(
            client_response=client_response,
            result=(client_response.status == HTTPStatus.OK),
        )

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
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.head(
            allow_redirects=True,
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
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
        return DockerRegistryClientAsyncHeadBlob(
            client_response=client_response,
            digest=digest,
            result=(client_response.status == HTTPStatus.OK),
        )

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
            accept = DockerRegistryClientAsync.DEFAULT_MEDIA_TYPES_MANIFEST
        protocol = kwargs.pop("protocol", DockerRegistryClientAsync.DEFAULT_PROTOCOL)

        headers = await self._get_request_headers(
            headers={"Accept": accept},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.head(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
        )

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
        return DockerRegistryClientAsyncHeadManifest(
            client_response=client_response,
            digest=digest,
            result=(client_response.status == HTTPStatus.OK),
        )

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
        protocol = DockerRegistryClientAsync._get_protocol_from_blob_upload(
            location=location
        )
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location=location
        )
        headers = await self._get_request_headers(
            headers={"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        if offset is not None:
            headers["Content-Range"] = f"{offset}-{offset + len(data) - 1}"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.patch(
            headers=headers,
            data=data,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            url=location,
            **kwargs,
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
        return DockerRegistryClientAsyncXBlobUpload(
            client_response=client_response,
            docker_upload_uuid=client_response.headers["Docker-Upload-UUID"],
            location=client_response.headers["Location"],
            range=client_response.headers["Range"],
        )

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
        return DockerRegistryClientAsyncPatchBlobUploadFromDisk(
            client_response=client_response,
            digest=hashing_generator.get_digest(),
            docker_upload_uuid=client_response.headers["Docker-Upload-UUID"],
            location=client_response.headers["Location"],
            range=client_response.headers["Range"],
        )

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
            headers={"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            image_name=image_name,
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
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.post(
            data=data,
            headers=headers,
            params=params,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
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
        return DockerRegistryClientAsyncXBlobUpload(
            client_response=client_response,
            docker_upload_uuid=client_response.headers.get("Docker-Upload-UUID", None),
            location=client_response.headers["Location"],
            range=client_response.headers["Range"],
        )

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
        protocol = DockerRegistryClientAsync._get_protocol_from_blob_upload(
            location=location
        )
        image_name = DockerRegistryClientAsync._get_image_name_from_blob_upload(
            location=location
        )
        headers = await self._get_request_headers(
            headers={"Content-Type": MediaTypes.APPLICATION_OCTET_STREAM},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        params = {"digest": digest}
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.put(
            data=data,
            headers=headers,
            params=params,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            url=location,
            **kwargs,
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
        return DockerRegistryClientAsyncPutBlobUpload(
            client_response=client_response,
            # Bad docs (code check: registry/handlers/blobupload.go:360)
            # content_range=client_response.headers["Content-Range"],
            digest=FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            ),
            location=client_response.headers["Location"],
        )

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
        return DockerRegistryClientAsyncPutBlobUpload(
            client_response=client_response,
            # Bad docs (code check: registry/handlers/blobupload.go:360)
            # content_range=client_response.headers["Content-Range"],
            digest=digest,
            location=client_response.headers["Location"],
        )

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
            headers={"Content-Type": media_type},
            image_name=image_name,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PUSH_PATTERN.format(
                image_name.resolve_image()
            ),
        )
        url = f"{protocol}://{image_name.resolve_endpoint()}/v2/{image_name.resolve_image()}/manifests/{identifier}"
        client_session = await self._get_client_session()
        proxy = await self._get_proxy(
            endpoint=image_name.resolve_endpoint(), protocol=protocol
        )
        return await client_session.put(
            headers=headers,
            data=manifest,
            proxy=proxy,
            proxy_auth=self.proxy_auth,
            ssl=self.ssl,
            url=url,
            **kwargs,
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
        return DockerRegistryClientAsyncPutManifest(
            client_response=client_response,
            digest=FormattedSHA256.parse(
                client_response.headers["Docker-Content-Digest"]
            ),
        )

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
        return DockerRegistryClientAsyncPutManifest(
            client_response=client_response, digest=digest
        )
