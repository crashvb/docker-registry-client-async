#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name,too-many-lines

"""DockerRegistryClientAsync tests."""

import asyncio
import hashlib
import json
import logging

from http import HTTPStatus
from pathlib import Path
from typing import Any, cast, Dict, Generator, TypedDict

import aiofiles
import pytest

from pytest_docker_registry_fixtures import (
    DockerRegistrySecure,
    ImageName as PDRFImageName,
    replicate_manifest_list,
)
from docker_registry_client_async import (
    DockerAuthentication,
    DockerMediaTypes,
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
    Indices,
    Manifest,
    MediaTypes,
)

from .testutils import get_test_data_path, hash_file

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.filterwarnings("ignore::DeprecationWarning:aiohttp.*:"),
    # Note: * The implicit "/library" namespace for DockerHub creates an asymmetry with local v2 registries.
    #         Reference: https://github.com/openshift/origin/issues/6711
    #         Compensate by specifying the namespace explicitly here, and it get_test_data().
    #       * Order of replication should be manifests, manifest lists, then tags.
    pytest.mark.push_image(
        # "library/busybox:1.30.1",
        "library/busybox@sha256:4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100",
        "library/busybox@sha256:abc043b5132f825e44eefffc35535b1f24bd3f1bb60b11943863563a46795fdc",
        "library/busybox@sha256:07717dd5f074de0cf4f7ca8f635cb63aef63d789f15a22ab482a3d27a0a1f881",
        "library/busybox@sha256:8dfe92e22300734a185375b6316d01aa1a2b0623d425a5e6e406771ba5642bf1",
        "library/busybox@sha256:3bdba83255bf7c575e31e129b2ddf1c0c32382e112cb051af6c5143c24a5ddbd",
        "library/busybox@sha256:bb87f507b42a6efe6f1d5382c826f914673a065f4d777b54b52f5414d688837a",
        "library/busybox@sha256:a09f03056efb5d3facb5077a9e58e83e9bba74ad4d343b2afa92c70b5ae01e2b",
        "library/busybox@sha256:0b671b6a323d86aa6165883f698b557ca257c3a3ffa1e3152ffb6467e7ac11b3",
        "library/busybox@sha256:4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d",  # ManifestList
        # "library/python:3.7.2-slim-stretch",
        "library/python@sha256:0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908",
        "library/python@sha256:09001905f918a977427cc6931a1cac84a8645b1ac2011fd3f40f625daf9a7fb1",
        "library/python@sha256:2d127b64fbb7a58ee8eb2c321f1bbd14548ab3191009cca7845b81155c9067bf",
        "library/python@sha256:59768566a74724d0feeca46cf4f21fd73850b56b8cbbc9dc46ef2f0e179064c5",
        "library/python@sha256:7505b822f9430bb8887037085e8b40d88ee02a424c075137f7d5b148a9e7131d",
        "library/python@sha256:de66a6835cfa722611fad3111edad211a66b489fd0a74db67487d860001fdc0c",
        "library/python@sha256:7d925740cfb767f08105b764b8126e29cd3bb6654a759aad09929206644c7bac",
        "library/python@sha256:78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a",  # ManifestList
    ),
]

LOGGER = logging.getLogger(__name__)


class TypingGetBinaryData(TypedDict):
    # pylint: disable=missing-class-docstring
    data: bytes
    digest: FormattedSHA256


class TypingGetTestDataLocal(TypedDict):
    # pylint: disable=missing-class-docstring
    image: str
    tag: str
    digests: Dict[str, FormattedSHA256]


class TypingGetManifest(TypedDict):
    # pylint: disable=missing-class-docstring
    image_name: ImageName
    manifest: Manifest


class TypingGetManifestJson(TypingGetManifest):
    # pylint: disable=missing-class-docstring
    manifest_json: Any


class TypingKnownGoodImage(TypingGetTestDataLocal):
    # pylint: disable=missing-class-docstring
    image_name: ImageName


def get_binary_data() -> Generator[TypingGetBinaryData, None, None]:
    """Binary test data."""
    blocks = [b'{"abcdefghijklmnopqrstuvwxyz": "0123456789"}']
    for block in blocks:
        yield {"data": block, "digest": FormattedSHA256.calculate(block)}


def get_identifier_map(known_good_image: TypingKnownGoodImage) -> Dict[ImageName, str]:
    """Constructs an identifier to media type mapping."""
    identifier_map = {}
    for media_type in known_good_image["digests"].keys():
        identifier_map[
            ImageName.parse(f"{known_good_image['image']}:{known_good_image['tag']}")
        ] = media_type
        if media_type != DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED:
            digest = known_good_image["digests"][media_type]
            identifier_map[
                ImageName.parse(f"{known_good_image['image']}@{digest}")
            ] = media_type
            identifier_map[
                ImageName.parse(
                    f"{known_good_image['image']}:{known_good_image['tag']}@{digest}"
                )
            ] = media_type
    return identifier_map


async def get_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
) -> TypingGetManifest:
    """Retrieves a distribution manifest v2 for a given 'known good' image."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    manifest_digest = known_good_image["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image['image']}@{manifest_digest}")

    LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
    response = await docker_registry_client_async.get_manifest(
        image_name, accept=media_type
    )
    manifest = response["manifest"]
    assert manifest.get_media_type() == media_type
    assert manifest.get_digest() == manifest_digest
    return {"image_name": image_name, "manifest": manifest}


async def get_manifest_json(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
) -> TypingGetManifestJson:
    """Retrieves a distribution manifest v2 for a given 'known good' image."""
    response = await get_manifest(docker_registry_client_async, known_good_image)
    response = cast(TypingGetManifestJson, response)
    response["manifest_json"] = response["manifest"].get_json()
    return response


def get_test_data() -> Generator[TypingGetTestDataLocal, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    images = [
        {
            "image": "library/busybox",
            "tag": "1.30.1",
            "digests": {
                # Note: Extracted 4fe88... from the manifest list for 'amd64'.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100"
                ),
                # Note: Extracted 4b6ad... from the 'RepoDigests' field (docker-inspect), after pulling by tag.
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d"
                ),
            },
            "tag_resolves_to_manifest_list": True,
        },
        {
            "image": "library/python",
            "tag": "3.7.2-slim-stretch",
            "digests": {
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908"
                ),
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a"
                ),
            },
            "tag_resolves_to_manifest_list": True,
        },
    ]
    for image in images:
        yield image


@pytest.fixture
def credentials_store_path(request) -> Path:
    """Retrieves the path of the credentials store to use for testing."""
    return get_test_data_path(request, "credentials_store.json")


@pytest.fixture
# HACK: Invoke replicate_manifest_list fixture to tell PDRF about the manifest lists we use for testing ...
async def docker_registry_client_async(
    credentials_store_path: Path,
    docker_registry_secure: DockerRegistrySecure,
    replicate_manifest_lists,
) -> DockerRegistryClientAsync:
    """Provides a DockerRegistryClientAsync instance."""
    # Do not use caching; get a new instance for each test
    async with DockerRegistryClientAsync(
        credentials_store=credentials_store_path, ssl=docker_registry_secure.ssl_context
    ) as docker_registry_client_async:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        await docker_registry_client_async.add_credentials(
            docker_registry_secure.endpoint, credentials
        )

        yield docker_registry_client_async


@pytest.fixture(scope="session")
# Required for asynchronous, session-scoped, fixtures
def event_loop():
    """Create an instance of the default event loop once for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(params=get_binary_data())
def known_binary_data(request) -> TypingGetBinaryData:
    """Provides 'known' binary data."""
    return request.param


@pytest.fixture(params=get_test_data())
def known_good_image(
    docker_registry_secure: DockerRegistrySecure, request
) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    image_name = ImageName.parse(request.param["image"])
    image_name.endpoint = docker_registry_secure.endpoint
    request.param["image"] = str(image_name)

    manifest_digest = request.param["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    request.param["image_name"] = ImageName.parse(
        f"{request.param['image']}:{request.param['tag']}@{manifest_digest}"
    )

    return request.param


@pytest.fixture(scope="session")
async def replicate_manifest_lists(docker_registry_secure: DockerRegistrySecure):
    """Replicates manifests lists to the secure docker registry for testing."""
    # pylint: disable=protected-access
    LOGGER.debug(
        "Replicating manifest lists into %s ...", docker_registry_secure.service_name
    )
    # Do not use DRCA from the fixture here, as we need "real" credentials ...
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        for image in get_test_data():
            if "tag_resolves_to_manifest_list" not in image:
                continue

            digest = image["digests"][DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2]
            image_name = ImageName(image["image"], digest=digest, tag=image["tag"])
            LOGGER.debug("- %s", image_name)

            scope = DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                image_name.image
            )
            auth_header_src = await docker_registry_client_async._get_request_headers(
                image_name, scope=scope
            )
            if not auth_header_src:
                LOGGER.warning(
                    "Unable to retrieve authentication headers for: %s", image_name
                )

            pdrf_image_name = PDRFImageName(
                image_name.resolve_image(),
                digest=image_name.resolve_digest(),
                endpoint=image_name.resolve_endpoint(),
                tag=image_name.resolve_tag(),
            )
            try:
                replicate_manifest_list(
                    pdrf_image_name,
                    docker_registry_secure.endpoint,
                    auth_header_dest=docker_registry_secure.auth_header,
                    auth_header_src=auth_header_src,
                    ssl_context_dest=docker_registry_secure.ssl_context,
                )
            except Exception as exception:  # pylint: disable=broad-except
                LOGGER.warning(
                    "Unable to replicate manifest list '%s': %s",
                    image_name,
                    exception,
                    exc_info=True,
                )


def test___init__(docker_registry_client_async: DockerRegistryClientAsync):
    """Test that the docker registry client can be instantiated."""
    assert docker_registry_client_async


async def test_add_credentials(docker_registry_client_async: DockerRegistryClientAsync):
    """Test that credentials can be assigned."""
    endpoint = "endpoint"
    credentials = "credentials"
    await docker_registry_client_async.add_credentials(endpoint, credentials)
    result = await docker_registry_client_async._get_credentials(endpoint)
    assert result == credentials


@pytest.mark.online
async def test__get_auth_token_dockerhub():
    """Test that an authentication token can be retrieved for index.docker.io."""
    endpoint = Indices.DOCKERHUB
    # Note: Using default credentials store from the test environment
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        credentials = await docker_registry_client_async._get_credentials(endpoint)
        if credentials:
            token = await docker_registry_client_async._get_auth_token(
                credentials=credentials,
                endpoint=endpoint,
                scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                    "busybox"
                ),
            )
            assert len(token) > 100
        else:
            pytest.skip("Unable to retrieve credentials for: %s", endpoint)


@pytest.mark.online
async def test__get_auth_token_dockerhub_anonymous():
    """Test that an authentication token can be retrieved for index.docker.io anonymously."""
    # Note: Using default credentials store from the test environment
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        token = await docker_registry_client_async._get_auth_token(
            endpoint=Indices.DOCKERHUB,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format("busybox"),
        )
        assert len(token) > 100


@pytest.mark.online
async def test__get_auth_token_quay():
    """Test that an authentication token can be retrieved for index.docker.io."""
    endpoint = Indices.QUAY
    # Note: Using default credentials store from the test environment
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        credentials = await docker_registry_client_async._get_credentials(endpoint)
        if credentials:
            token = await docker_registry_client_async._get_auth_token(
                credentials=credentials,
                endpoint=endpoint,
                scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format(
                    "crio/busybox"
                ),
            )
            assert len(token) > 100
        else:
            pytest.skip("Unable to retrieve credentials for: %s", endpoint)


async def test__get_client_session(
    docker_registry_client_async: DockerRegistryClientAsync,
):
    """Test that the client session can be retrieved."""
    assert await docker_registry_client_async._get_client_session()


@pytest.mark.parametrize(
    "endpoint,auth",
    [
        ("endpoint:port", "dXNlcm5hbWU6cGFzc3dvcmQ="),
        ("endpoint2:port2", "dXNlcm5hbWUyOnBhc3N3b3JkMg=="),
    ],
)
async def test__get_credentials(
    docker_registry_client_async: DockerRegistryClientAsync, endpoint: str, auth: str
):
    """Test that credentials can be retrieved."""
    result = await docker_registry_client_async._get_credentials(endpoint)
    assert result == auth


@pytest.mark.parametrize(
    "endpoint,auth",
    [
        ("endpoint:port", "dXNlcm5hbWU6cGFzc3dvcmQ="),
        ("endpoint2:port2", "dXNlcm5hbWUyOnBhc3N3b3JkMg=="),
    ],
)
async def test__get_request_headers_basic_auth(
    docker_registry_client_async: DockerRegistryClientAsync, endpoint: str, auth: str
):
    """Test request headers retrieval."""
    image_name = ImageName("", endpoint=endpoint)
    existing_header = "existing-header"
    headers = await docker_registry_client_async._get_request_headers(
        image_name, {existing_header: "1"}
    )
    assert auth in headers["Authorization"]
    assert existing_header in headers


@pytest.mark.online
async def test__get_request_headers_token_anonymous():
    """Test request headers retrieval."""
    image_name = ImageName("", endpoint=Indices.DOCKERHUB)
    existing_header = "existing-header"
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        headers = await docker_registry_client_async._get_request_headers(
            image_name, {existing_header: "1"}
        )
        assert headers["Authorization"].startswith("Bearer ")
        assert len(headers["Authorization"]) > 100
        assert existing_header in headers


@pytest.mark.parametrize(
    "endpoint,auth",
    [
        ("endpoint:port", "dXNlcm5hbWU6cGFzc3dvcmQ="),
        ("endpoint2:port2", "dXNlcm5hbWUyOnBhc3N3b3JkMg=="),
    ],
)
async def test__load_credentials(
    docker_registry_client_async: DockerRegistryClientAsync, endpoint: str, auth: str
):
    """Test that credentials can be loaded from the credentials store."""
    await docker_registry_client_async._load_credentials()
    found = False
    for key in docker_registry_client_async.credentials:
        if endpoint in key:
            assert docker_registry_client_async.credentials[key]["auth"] == auth
            found = True
    assert found


@pytest.mark.online_deletion
async def test__delete_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )
    await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"]
    )

    LOGGER.debug("Deleting blob: %s ...", known_binary_data["digest"])
    client_response = await docker_registry_client_async._delete_blob(
        manifest_data["image_name"], known_binary_data["digest"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED
    assert client_response.headers["Content-Length"] == "0"
    # Bad docs (code check: registry/handlers/blob.go:97)
    # assert client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]


@pytest.mark.online_deletion
async def test_delete_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )
    await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"]
    )

    LOGGER.debug("Deleting blob: %s ...", known_binary_data["digest"])
    response = await docker_registry_client_async.delete_blob(
        manifest_data["image_name"], known_binary_data["digest"]
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online_deletion
async def test__delete_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    LOGGER.debug("Deleting blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._delete_blob_upload(
        response["location"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.NO_CONTENT
    # assert client_response.headers["Content-Length"] == "0"  # Bad docs


@pytest.mark.online_deletion
async def test_delete_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    response = await docker_registry_client_async.delete_blob_upload(
        response["location"]
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online_deletion
async def test__delete_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )

    # Modify the manifest ...
    manifest = manifest_data["manifest"]
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data["image_name"]
    image_name.digest = manifest.get_digest()
    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
    response = await docker_registry_client_async.put_manifest(image_name, manifest)
    assert response["digest"] == manifest.get_digest()

    # ... then delete it ...
    LOGGER.debug("Deleting manifest: %s ...", image_name)
    client_response = await docker_registry_client_async._delete_manifest(image_name)
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED


@pytest.mark.online_deletion
async def test_delete_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )

    # Modify the manifest ...
    manifest = manifest_data["manifest"]
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data["image_name"]
    image_name.digest = manifest.get_digest()
    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
    response = await docker_registry_client_async.put_manifest(image_name, manifest)
    assert response["digest"] == manifest.get_digest()

    # ... then delete it ...
    LOGGER.debug("Deleting manifest: %s ...", image_name)
    response = await docker_registry_client_async.delete_manifest(image_name)
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online
async def test__get_blob_config(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    client_response = await docker_registry_client_async._get_blob(
        manifest_data["image_name"], config_digest, accept=config["mediaType"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert int(client_response.headers["Content-Length"]) == int(config["size"])
    assert (
        client_response.headers["Content-Type"] == MediaTypes.APPLICATION_OCTET_STREAM
    )

    data = await client_response.read()
    digest = FormattedSHA256(hashlib.sha256(data).hexdigest())
    assert digest == config_digest
    # TODO: Docker-Content-Digest is returned by a local v2 registry, but not Docker Hub ?!?
    # assert digest == client_response.headers["Docker-Content-Digest"]
    assert len(data) == config["size"]


@pytest.mark.online
async def test__get_blob_layer(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    layer = manifest_data["manifest_json"]["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    layer_digest = layer["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], layer_digest
    )
    client_response = await docker_registry_client_async._get_blob(
        manifest_data["image_name"], layer_digest, accept=layer["mediaType"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert int(client_response.headers["Content-Length"]) == int(layer["size"])
    assert (
        client_response.headers["Content-Type"] == MediaTypes.APPLICATION_OCTET_STREAM
    )

    data = await client_response.read()
    digest = FormattedSHA256(hashlib.sha256(data).hexdigest())
    assert digest == layer_digest
    # TODO: Docker-Content-Digest is returned by a local v2 registry, but not Docker Hub ?!?
    # assert digest == client_response.headers["Docker-Content-Digest"]
    assert len(data) == layer["size"]


@pytest.mark.online
async def test_get_blob(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    layer = manifest_data["manifest_json"]["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    layer_digest = layer["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], layer_digest
    )
    response = await docker_registry_client_async.get_blob(
        manifest_data["image_name"], layer_digest, accept=layer["mediaType"]
    )
    assert all(x in response for x in ["blob", "client_response"])

    assert response["blob"]


@pytest.mark.online
async def test_get_blob_to_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image,
    tmp_path: Path,
):
    """Test that the image blobs (image configurations) can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == config["digest"]


@pytest.mark.online
async def test_get_blob_to_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image,
    tmp_path: Path,
):
    """Test that the image blobs (image configurations) can be retrieved to disk synchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == config["digest"]


@pytest.mark.online_modification
async def test__get_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Retrieving blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._get_blob_upload(
        response["location"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.NO_CONTENT
    # Bad Docs (code check: registry/handlers/blobupload.go:119)
    # assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test_get_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Retrieving blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.get_blob_upload(response["location"])
    assert all(x in response for x in ["client_response", "location", "range"])
    assert response["range"] == "0-0"


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test__get_catalog(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image catalog can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image['image']}:{known_good_image['tag']}"
    )
    LOGGER.debug("Retrieving catalog ...")
    client_response = await docker_registry_client_async._get_catalog(image_name)
    assert client_response
    assert client_response.status == HTTPStatus.OK

    catalog = json.loads(await client_response.text())
    assert "repositories" in catalog
    assert image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test_get_catalog(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image catalog can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image['image']}:{known_good_image['tag']}"
    )
    LOGGER.debug("Retrieving catalog ...")
    response = await docker_registry_client_async.get_catalog(image_name)
    assert all(x in response for x in ["catalog", "client_response"])

    catalog = response["catalog"]
    assert "repositories" in catalog
    assert image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
async def test__get_manifest(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        client_response = await docker_registry_client_async._get_manifest(
            image_name, accept=media_type
        )
        assert client_response
        assert client_response.status == HTTPStatus.OK

        data = await client_response.read()
        digest = FormattedSHA256(hashlib.sha256(data).hexdigest())
        if image_name.digest:
            assert digest == image_name.resolve_digest()
            assert digest == client_response.headers["Docker-Content-Digest"]
        else:
            LOGGER.debug(
                "Skipping digest check for: %s (%s)",
                image_name,
                identifier_map[image_name],
            )

        assert json.loads(await client_response.text())
        assert client_response.headers["Content-Type"] == media_type


@pytest.mark.online
async def test_get_manifest(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type
        )
        assert all(x in response for x in ["client_response", "manifest"])

        manifest = response["manifest"]
        assert manifest

        if image_name.digest:
            assert manifest.get_digest() == image_name.resolve_digest()
        else:
            LOGGER.debug("Skipping digest check for: %s (%s)", image_name, media_type)

        media_type = manifest.get_media_type()

        manifest_json = manifest.get_json()
        if media_type == DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED:
            assert manifest_json["schemaVersion"] == 1
            assert manifest_json["name"] == image_name.resolve_image()
            assert manifest_json["tag"] == image_name.resolve_tag()
        elif media_type == DockerMediaTypes.DISTRIBUTION_MANIFEST_V2:
            assert manifest_json["schemaVersion"] == 2
            assert manifest_json["mediaType"] == media_type
        elif media_type == DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2:
            assert manifest_json["schemaVersion"] == 2
            assert manifest_json["mediaType"] == media_type
            assert len(manifest_json["manifests"]) > 0
            sub_manifest = manifest_json["manifests"][0]
            assert all(
                x in sub_manifest for x in ["digest", "mediaType", "platform", "size"]
            )
        else:
            LOGGER.warning("No assertions defined for media type: %s!", media_type)


@pytest.mark.online
async def test_get_manifest_sanity_check():
    """Test that 'python' works against index.docker.io."""
    # Note: Using default credentials store from the test environment
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        image_name = ImageName.parse("python")
        media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type
        )
        assert all(x in response for x in ["client_response", "manifest"])
        assert response["manifest"]


@pytest.mark.online
async def test_get_manifest_to_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    digest = known_good_image["digests"][DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    image_name = ImageName.parse(f"{known_good_image['image']}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])
    assert response["digest"] == image_name.resolve_digest()
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == image_name.resolve_digest()


@pytest.mark.online
async def test_get_manifest_to_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk synchronously."""
    digest = known_good_image["digests"][DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    image_name = ImageName.parse(f"{known_good_image['image']}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, file_is_async=False
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])
    assert response["digest"] == image_name.resolve_digest()
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == image_name.resolve_digest()


@pytest.mark.online
async def test__get_tags(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image['image']}:{known_good_image['tag']}"
    )
    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    client_response = await docker_registry_client_async._get_tags(image_name)
    assert client_response
    assert client_response.status == HTTPStatus.OK

    tags = json.loads(await client_response.text())
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test_get_tag_list(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image['image']}:{known_good_image['tag']}"
    )
    LOGGER.debug("Retrieving tag list for: %s ...", image_name)
    response = await docker_registry_client_async.get_tag_list(image_name)
    assert all(x in response for x in ["client_response", "tags"])

    result = False
    for entry in response["tags"]:
        if entry.resolve_tag() == image_name.resolve_tag():
            result = True
            break
    assert result


@pytest.mark.online
async def test_get_tags(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image['image']}:{known_good_image['tag']}"
    )
    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    response = await docker_registry_client_async.get_tags(image_name)
    assert all(x in response for x in ["client_response", "tags"])

    tags = response["tags"]
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test__get_version(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the endpoint implements Docker Registry API v2."""
    LOGGER.debug(
        "Retrieving version from %s ...", known_good_image["image_name"].endpoint
    )
    client_response = await docker_registry_client_async._get_version(
        known_good_image["image_name"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert client_response.content_type == "application/json"
    assert client_response.headers["Docker-Distribution-Api-Version"] == "registry/2.0"


@pytest.mark.online
async def test__get_version_dockerhub():
    """Test that the endpoint implements Docker Registry API v2."""
    # Note: Using default credentials store from the test environment
    image_name = ImageName("")
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        LOGGER.debug("Retrieving version from %s ...", image_name.resolve_endpoint())
        client_response = await docker_registry_client_async._get_version(image_name)
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert client_response.content_type == "application/json"
    assert client_response.headers["Docker-Distribution-Api-Version"] == "registry/2.0"


@pytest.mark.online
async def test_get_version(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the endpoint implements Docker Registry API v2."""
    LOGGER.debug(
        "Retrieving version from %s ...", known_good_image["image_name"].endpoint
    )
    response = await docker_registry_client_async.get_version(
        known_good_image["image_name"]
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online
async def test__head_blob(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Checking blob: %s/%s ...", manifest_data["image_name"], config_digest)
    client_response = await docker_registry_client_async._head_blob(
        manifest_data["image_name"], config_digest
    )

    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert int(client_response.headers["Content-Length"]) == int(config["size"])
    assert (
        client_response.headers["Content-Type"] == MediaTypes.APPLICATION_OCTET_STREAM
    )
    # TODO: Docker-Content-Digest is returned by a local v2 registry, but not Docker Hub ?!?
    # assert client_response.headers["Docker-Content-Digest"] == config_digest


@pytest.mark.online
async def test_head_blob(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Checking blob: %s/%s ...", manifest_data["image_name"], config_digest)
    response = await docker_registry_client_async.head_blob(
        manifest_data["image_name"], config_digest
    )
    assert all(x in response for x in ["client_response", "digest", "result"])
    # TODO: Docker-Content-Digest is returned by a local v2 registry, but not Docker Hub ?!?
    # assert response["digest"] == config_digest
    assert response["result"]

    # Negative test
    sha256_old = config_digest
    config_digest = config_digest.replace("1", "2")
    assert config_digest != sha256_old
    response = await docker_registry_client_async.head_blob(
        manifest_data["image_name"], config_digest
    )
    assert all(x in response for x in ["client_response", "digest", "result"])
    assert not response["result"]


@pytest.mark.online
async def test__head_manifest(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image).keys()
    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        client_response = await docker_registry_client_async._head_manifest(image_name)
        assert client_response
        assert client_response.status == HTTPStatus.OK

        if image_name.digest:
            assert (
                client_response.headers["Docker-Content-Digest"]
                == image_name.resolve_digest()
            )
        else:
            LOGGER.debug("Skipping digest check for: %s", image_name)


@pytest.mark.online
async def test_head_manifest(
    docker_registry_client_async: DockerRegistryClientAsync, known_good_image
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image).keys()
    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        response = await docker_registry_client_async.head_manifest(image_name)
        assert all(x in response for x in ["client_response", "digest", "result"])

        if image_name.digest:
            assert response["digest"] == image_name.resolve_digest()
        else:
            LOGGER.debug("Skipping digest check for: %s", image_name)
        assert response["result"]

        # Negative test
        if image_name.digest:
            sha256_old = image_name.digest.sha256
            image_name.digest = FormattedSHA256(
                image_name.digest.sha256.replace("1", "2")
            )
            assert image_name.digest.sha256 != sha256_old
            response = await docker_registry_client_async.head_manifest(image_name)
            assert all(x in response for x in ["client_response", "digest", "result"])
            assert not response["result"]


@pytest.mark.online_modification
async def test__patch_blob_upload_chunked(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (chunked) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    chunk_size = 5
    upload_length = 0
    location = response["location"]
    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    for offset in range(0, len(known_binary_data["data"]), chunk_size):
        chunk = known_binary_data["data"][offset : offset + chunk_size]
        client_response = await docker_registry_client_async._patch_blob_upload(
            location, chunk, offset=offset
        )
        upload_length += len(chunk)
        assert client_response
        assert (
            client_response.status == HTTPStatus.ACCEPTED
        )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:178)
        assert client_response.headers["Content-Length"] == "0"
        assert client_response.headers["Docker-Upload-UUID"]
        assert client_response.headers["Location"]
        assert client_response.headers["Range"] == f"0-{upload_length - 1}"
        location = client_response.headers["Location"]


@pytest.mark.online_modification
async def test__patch_blob_upload_stream(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._patch_blob_upload(
        response["location"], known_binary_data["data"]
    )
    assert client_response
    assert (
        client_response.status == HTTPStatus.ACCEPTED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:178)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == f"0-{len(known_binary_data['data']) - 1}"


@pytest.mark.online_modification
async def test_patch_blob_upload_stream(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )


@pytest.mark.online_modification
async def test_patch_blob_upload_from_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert all(x in response for x in ["client_response", "digest", "size"])
    digest = response["digest"]

    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.patch_blob_upload_from_disk(
            response["location"], file
        )
    assert all(
        x in response
        for x in [
            "client_response",
            "digest",
            "docker_upload_uuid",
            "location",
            "range",
        ]
    )
    assert response["digest"] == digest


@pytest.mark.online_modification
async def test_patch_blob_upload_from_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    with path.open(mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            file_is_async=False,
            accept=config["mediaType"],
        )
    assert all(x in response for x in ["client_response", "digest", "size"])
    digest = response["digest"]

    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    with path.open("r+b") as file:
        response = await docker_registry_client_async.patch_blob_upload_from_disk(
            response["location"], file, file_is_async=False
        )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )
    assert response["digest"] == digest


@pytest.mark.skip(
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke"
    "blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__post_blob_monolithic(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug(
        "Initiating monolithic blob upload: %s ...", manifest_data["image_name"]
    )
    client_response = await docker_registry_client_async._post_blob(
        manifest_data["image_name"],
        data=known_binary_data["data"],
        digest=known_binary_data["digest"],
    )
    assert client_response
    assert client_response.status == HTTPStatus.CREATED
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test__post_blob_resumable(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug(
        "Initiating resumable blob upload: %s ...", manifest_data["image_name"]
    )
    client_response = await docker_registry_client_async._post_blob(
        manifest_data["image_name"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test__post_blob_mount(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the blobs can be mounted from other repositories."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )

    layer = manifest_data["manifest_json"]["layers"][0]
    layer_digest = FormattedSHA256.parse(layer["digest"])

    destination = manifest_data["image_name"].clone()
    destination.image += __name__

    LOGGER.debug(
        "Initiating blob mount: %s/%s -> %s ...",
        manifest_data["image_name"],
        layer_digest,
        destination,
    )
    client_response = await docker_registry_client_async._post_blob(
        destination, source=manifest_data["image_name"], digest=layer_digest
    )
    assert client_response
    # Note: Explicitly 201 if mounted; 202 indicates mount failed, and a non-mount blob upload was started ...
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # (code check: registry/handlers/blobupload.go:100)
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Content-Digest"] == layer_digest
    assert "Docker-Upload-UUID" not in client_response.headers
    assert client_response.headers["Location"]
    assert "Range" not in client_response.headers


@pytest.mark.online_modification
async def test_post_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )


@pytest.mark.online_modification
async def test__put_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"]
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert (
        client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]
    )
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_patch(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"]
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert (
        client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]
    )
    assert client_response.headers["Location"]


@pytest.mark.skip(
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke"
    "blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_post(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug(
        "Initiating blob upload (with data): %s ...", manifest_data["image_name"]
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], data=known_binary_data["data"]
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"]
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert (
        client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]
    )
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_put(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload (with data): %s ...", response["location"])
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"],
        known_binary_data["digest"],
        data=known_binary_data["data"],
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert (
        client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]
    )
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test_put_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Patching blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    response = await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"]
    )
    assert all(x in response for x in ["client_response", "digest", "location"])
    assert response["client_response"].headers["Content-Length"] == "0"
    assert (
        response["client_response"].headers["Docker-Content-Digest"]
        == known_binary_data["digest"]
    )
    assert response["client_response"].headers["Location"]


@pytest.mark.online_modification
async def test_put_blob_upload_from_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.put_blob_upload_from_disk(
            response["location"], config_digest, file
        )
    assert all(x in response for x in ["client_response", "digest", "location"])
    assert response["digest"] == config_digest


@pytest.mark.online_modification
async def test_put_blob_upload_from_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...", manifest_data["image_name"], config_digest
    )
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    manifest_data["image_name"].image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data["image_name"])
    response = await docker_registry_client_async.post_blob(manifest_data["image_name"])
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload: %s ...", response["location"])
    with path.open("r+b") as file:
        response = await docker_registry_client_async.put_blob_upload_from_disk(
            response["location"], config_digest, file, file_is_async=False
        )
    assert all(x in response for x in ["client_response", "digest", "location"])
    assert response["digest"] == config_digest


@pytest.mark.online_modification
async def test__put_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type
        )
        assert all(x in response for x in ["client_response", "manifest"])

        if image_name.tag:
            image_name.tag += __name__
        LOGGER.debug(
            "Storing manifest: %s (%s) ...",
            image_name,
            response["manifest"].get_digest(),
        )
        client_response = await docker_registry_client_async._put_manifest(
            image_name,
            response["manifest"].get_bytes(),
            media_type=response["manifest"].get_media_type(),
        )
        assert client_response
        assert client_response.status == HTTPStatus.CREATED

        if image_name.digest:
            assert (
                client_response.headers["Docker-Content-Digest"]
                == image_name.resolve_digest()
            )
        else:
            LOGGER.debug("Skipping digest check for: %s (%s)", image_name, media_type)


@pytest.mark.online_modification
async def test_put_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type
        )
        assert all(x in response for x in ["client_response", "manifest"])

        manifest = response["manifest"]
        assert manifest

        # Put the manifest as is ...
        if image_name.tag:
            image_name.tag += __name__
        LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
        response = await docker_registry_client_async.put_manifest(image_name, manifest)
        assert all(x in response for x in ["client_response", "digest"])

        if image_name.digest:
            assert response["digest"] == image_name.resolve_digest()
        assert response["digest"] == manifest.get_digest()

        # Modify the manifest ...
        digest_old = manifest.get_digest()
        manifest.json["x"] = 1
        manifest._set_json(manifest.get_json())
        assert manifest.get_digest() != digest_old

        # ... and put it again ...
        image_name.digest = manifest.get_digest()
        LOGGER.debug(
            "Storing manifest (modified): %s (%s) ...",
            image_name,
            manifest.get_digest(),
        )
        response = await docker_registry_client_async.put_manifest(image_name, manifest)
        assert all(x in response for x in ["client_response", "digest"])

        assert response["digest"] == manifest.get_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image['image']}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file
        )
    assert all(x in response for x in ["client_response", "digest", "size"])

    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s ...", image_name)
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.put_manifest_from_disk(
            image_name, file, media_type=media_type
        )
    assert all(x in response for x in ["client_response", "digest"])
    assert response["digest"] == image_name.resolve_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image['image']}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, file_is_async=False
        )
    assert all(x in response for x in ["client_response", "digest", "size"])

    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s ...", image_name)
    with path.open("r+b") as file:
        response = await docker_registry_client_async.put_manifest_from_disk(
            image_name, file, file_is_async=False, media_type=media_type
        )
    assert all(x in response for x in ["client_response", "digest"])
    assert response["digest"] == image_name.resolve_digest()


# TODO: Total image pull (with exists() checks)
# TODO: Total image push
