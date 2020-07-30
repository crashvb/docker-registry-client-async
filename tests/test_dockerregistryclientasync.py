#!/usr/bin/env python

# pylint: disable=redefined-outer-name,protected-access

"""DockerRegistryClientAsync tests."""

import hashlib
import json
import logging

from http import HTTPStatus
from itertools import chain
from pathlib import Path
from typing import Dict, Generator, TypedDict

import aiofiles
import pytest

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

from .localregistry import (
    docker_client,
    get_test_data_local,
    known_good_image_local,
    TypingGetTestDataLocal,
    TypingKnownGoodImage,
    pytest_registry,
)
from .testutils import get_test_data_path, hash_file

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.filterwarnings("ignore::DeprecationWarning:aiohttp.*:"),
]

LOGGER = logging.getLogger(__name__)


class TypingGetBinaryData(TypedDict):
    # pylint: disable=missing-class-docstring
    data: bytes
    digest: FormattedSHA256


class TypingGetManifest(TypedDict):
    # pylint: disable=missing-class-docstring
    image_name: ImageName
    manifest: Manifest


def get_test_data_remote() -> Generator[TypingGetTestDataLocal, None, None]:
    """Dynamically initializes test data for a remote readonly registry."""
    images = [
        {
            "image": "busybox",
            "tag": "1.30.1",
            "digests": {
                # TODO: Used accept=mediatype to pull, got 4cf55... from 'Docker-Content-Digest' response header ...
                #       ... but it doesn't work (404)!
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED: FormattedSHA256(
                    "4cf55a9a8322fad1d746a5094a14b900cb748a44f64fe03ac6d4c2167c463c49"
                ),
                # Pull the manifest list to get the 'amd64' digest: 4fe88...
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "4fe8827f51a5e11bb83afa8227cbccb402df840d32c6b633b7ad079bc8144100"
                ),
                # Note: Pulled image by tag, then used docker-inspect to get the digest from 'RepoDigests': 4b6ad...
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "4b6ad3a68d34da29bf7c8ccb5d355ba8b4babcad1f99798204e7abb43e54ee3d"
                ),
            },
        },
        {
            "image": "library/python",
            "tag": "3.7.2-slim-stretch",
            "digests": {
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED: FormattedSHA256(
                    "78d762d2bb4a397a5066981905cfc5ba0d5446aa0109650f76388d53f0791a7d"
                ),
                DockerMediaTypes.DISTRIBUTION_MANIFEST_V2: FormattedSHA256(
                    "0005ba40bf87e486d7061ca0112123270e4a6088b5071223c8d467db3dbba908"
                ),
                DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2: FormattedSHA256(
                    "78320634b63efb52f591a7d69d5a50076ce76e7b72c4b45c1e4ddad90c39870a"
                ),
            },
        },
    ]
    for image in images:
        yield image


def get_binary_data() -> Generator[TypingGetBinaryData, None, None]:
    """Binary test data."""
    blocks = [b'{"abcdefghijklmnopqrstuvwxyz": "0123456789"}']
    for block in blocks:
        yield {"data": block, "digest": FormattedSHA256.calculate(block)}


def get_identifier_map(known_good_image: TypingKnownGoodImage,) -> Dict[ImageName, str]:
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
    **kwargs,
) -> TypingGetManifest:
    """Retrieves a distribution manifest v2 for a given 'known good' image."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    manifest_digest = known_good_image["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image['image']}@{manifest_digest}")
    if "protocol" in known_good_image:
        kwargs["protocol"] = known_good_image["protocol"]

    LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
    response = await docker_registry_client_async.get_manifest(
        image_name, accept=media_type, **kwargs
    )
    manifest = response["manifest"]
    assert manifest.get_media_type() == media_type
    assert manifest.get_digest() == manifest_digest
    return {"image_name": image_name, "manifest": manifest}


async def get_manifest_json(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image: TypingKnownGoodImage,
    **kwargs,
) -> Dict:
    """Retrieves a distribution manifest v2 for a given 'known good' image."""
    response = await get_manifest(
        docker_registry_client_async, known_good_image, **kwargs
    )
    return {"manifest_json": response["manifest"].get_json(), **response}


@pytest.fixture
def credentials_store_path(request) -> Path:
    """Retrieves the path of the credentials store to use for testing."""
    return get_test_data_path(request, "credentials_store.json")


@pytest.fixture
async def docker_registry_client_async() -> DockerRegistryClientAsync:
    """Provides a DockerRegistryClientAsync instance."""
    # Do not use caching; get a new instance for each test
    async with DockerRegistryClientAsync() as docker_registry_client_async:
        yield docker_registry_client_async


@pytest.fixture(params=chain(get_test_data_local(), get_test_data_remote()))
def known_good_image_remote(request, pytest_registry: str) -> TypingGetTestDataLocal:
    """Provides 'known good' metadata for a remote image that is readonly."""
    request.param["image"] = request.param["image"].format(pytest_registry)
    return request.param


@pytest.fixture(params=get_binary_data())
def known_binary_data(request) -> TypingGetBinaryData:
    """Provides 'known' binary data."""
    return request.param


def test___init__(docker_registry_client_async: DockerRegistryClientAsync):
    """Test that the docker registry client can be instantiated."""
    assert docker_registry_client_async


async def test__get_client_session(
    docker_registry_client_async: DockerRegistryClientAsync,
):
    """Test that the client session can be retrieved."""
    assert await docker_registry_client_async._get_client_session()


@pytest.mark.online
async def test__get_auth_token_dockerhub(
    docker_registry_client_async: DockerRegistryClientAsync,
):
    """Test that an authentication token can be retrieved for index.docker.io."""
    endpoint = Indices.DOCKERHUB
    credentials = await docker_registry_client_async._get_credentials(endpoint)
    if credentials:
        token = await docker_registry_client_async._get_auth_token(
            credentials=credentials,
            endpoint=endpoint,
            scope=DockerAuthentication.SCOPE_REPOSITORY_PULL_PATTERN.format("busybox"),
        )
        assert len(token) > 100
    else:
        LOGGER.warning("Unable to retrieve credentials for: %s", endpoint)


@pytest.mark.online
async def test__get_auth_token_quay(
    docker_registry_client_async: DockerRegistryClientAsync,
):
    """Test that an authentication token can be retrieved for index.docker.io."""
    endpoint = Indices.QUAY
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
        LOGGER.warning("Unable to retrieve credentials for: %s", endpoint)


@pytest.mark.parametrize(
    "endpoint,auth",
    [
        ("endpoint:port", "dXNlcm5hbWU6cGFzc3dvcmQ="),
        ("endpoint2:port2", "dXNlcm5hbWUyOnBhc3N3b3JkMg=="),
    ],
)
async def test__get_credentials(
    docker_registry_client_async: DockerRegistryClientAsync,
    credentials_store_path: Path,
    endpoint: str,
    auth: str,
):
    """Test that credentials can be retrieved."""
    docker_registry_client_async.credentials_store = credentials_store_path
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
    docker_registry_client_async: DockerRegistryClientAsync,
    credentials_store_path: Path,
    endpoint: str,
    auth: str,
):
    """Test request headers retrieval."""
    image_name = ImageName(None, endpoint=endpoint)
    existing_header = "existing-header"
    docker_registry_client_async.credentials_store = credentials_store_path
    headers = await docker_registry_client_async._get_request_headers(
        image_name, {existing_header: "1"}
    )
    assert auth in headers["Authorization"]
    assert existing_header in headers


@pytest.mark.online_deletion
async def test__delete_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )
    await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
    )

    client_response = await docker_registry_client_async._delete_blob(
        manifest_data["image_name"], known_binary_data["digest"], **kwargs
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED
    assert client_response.headers["Content-Length"] == "0"
    # assert client_response.headers["Docker-Content-Digest"] == known_binary_data["digest"]  # Bad docs (code check: registry/handlers/blob.go:97)


@pytest.mark.online_deletion
async def test_delete_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )
    await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
    )

    response = await docker_registry_client_async.delete_blob(
        manifest_data["image_name"], known_binary_data["digest"], **kwargs
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online_deletion
async def test__delete_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    client_response = await docker_registry_client_async._delete_blob_upload(
        response["location"], **kwargs
    )
    assert client_response
    assert client_response.status == HTTPStatus.NO_CONTENT
    # assert client_response.headers["Content-Length"] == "0"  # Bad docs


@pytest.mark.online_deletion
async def test_delete_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    response = await docker_registry_client_async.delete_blob_upload(
        response["location"], **kwargs
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online_deletion
async def test__delete_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    # Modify the manifest ...
    manifest = manifest_data["manifest"]
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data["image_name"]
    image_name.digest = manifest.get_digest()
    response = await docker_registry_client_async.put_manifest(
        image_name, manifest, **kwargs
    )
    assert response["digest"] == manifest.get_digest()

    # ... then delete it ...
    client_response = await docker_registry_client_async._delete_manifest(
        image_name, **kwargs
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED


@pytest.mark.online_deletion
async def test_delete_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    # Modify the manifest ...
    manifest = manifest_data["manifest"]
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data["image_name"]
    image_name.digest = manifest.get_digest()
    response = await docker_registry_client_async.put_manifest(
        image_name, manifest, **kwargs
    )
    assert response["digest"] == manifest.get_digest()

    # ... then delete it ...
    response = await docker_registry_client_async.delete_manifest(image_name, **kwargs)
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online
async def test__get_blob_config(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    client_response = await docker_registry_client_async._get_blob(
        manifest_data["image_name"], config_digest, accept=config["mediaType"], **kwargs
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
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    layer = manifest_data["manifest_json"]["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    layer_digest = layer["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        layer_digest,
    )
    client_response = await docker_registry_client_async._get_blob(
        manifest_data["image_name"], layer_digest, accept=layer["mediaType"], **kwargs
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
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    layer = manifest_data["manifest_json"]["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    layer_digest = layer["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        layer_digest,
    )
    response = await docker_registry_client_async.get_blob(
        manifest_data["image_name"], layer_digest, accept=layer["mediaType"], **kwargs
    )
    assert all(x in response for x in ["blob", "client_response"])

    assert response["blob"]


@pytest.mark.online
async def test_get_blob_to_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image blobs (image configurations) can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            **kwargs,
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
    known_good_image_remote: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image blobs (image configurations) can be retrieved to disk synchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
            **kwargs,
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    client_response = await docker_registry_client_async._get_blob_upload(
        response["location"]
    )
    assert client_response
    assert client_response.status == HTTPStatus.NO_CONTENT
    # assert client_response.headers["Content-Length"] == "0"  # Bad Docs (code check: registry/handlers/blobupload.go:119)
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test_get_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    response = await docker_registry_client_async.get_blob_upload(
        response["location"], **kwargs
    )
    assert all(x in response for x in ["client_response", "location", "range"])
    assert response["range"] == "0-0"


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test__get_catalog(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image catalog can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_local['image']}:{known_good_image_local['tag']}"
    )
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug("Retrieving catalog ...")
    client_response = await docker_registry_client_async._get_catalog(
        image_name, **kwargs
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK

    catalog = json.loads(await client_response.text())
    assert "repositories" in catalog
    assert image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test_get_catalog(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image catalog can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_local['image']}:{known_good_image_local['tag']}"
    )
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug("Retrieving catalog ...")
    response = await docker_registry_client_async.get_catalog(image_name, **kwargs)
    assert all(x in response for x in ["catalog", "client_response"])

    catalog = response["catalog"]
    assert "repositories" in catalog
    assert image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
async def test__get_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image_remote)
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        client_response = await docker_registry_client_async._get_manifest(
            image_name, accept=media_type, **kwargs
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

        manifest = json.loads(await client_response.text())
        assert manifest
        content_type = client_response.headers["Content-Type"]
        assert content_type == identifier_map[image_name]


@pytest.mark.online
async def test_get_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image_remote)
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type, **kwargs
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
async def test_get_manifest_to_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    digest = known_good_image_remote["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    image_name = ImageName.parse(f"{known_good_image_remote['image']}@{digest}")
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, **kwargs
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
    known_good_image_remote: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk synchronously."""
    digest = known_good_image_remote["digests"][
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    ]
    image_name = ImageName.parse(f"{known_good_image_remote['image']}@{digest}")
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, file_is_async=False, **kwargs
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
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_remote['image']}:{known_good_image_remote['tag']}"
    )
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    client_response = await docker_registry_client_async._get_tags(image_name, **kwargs)
    assert client_response
    assert client_response.status == HTTPStatus.OK

    tags = json.loads(await client_response.text())
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test_get_tags(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_remote['image']}:{known_good_image_remote['tag']}"
    )
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    response = await docker_registry_client_async.get_tags(image_name, **kwargs)
    assert all(x in response for x in ["client_response", "tags"])

    tags = response["tags"]
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test__get_version(
    docker_registry_client_async: DockerRegistryClientAsync, **kwargs
):
    """Test that the endpoint implements Docker Registry API v2."""
    client_response = await docker_registry_client_async._get_version(
        ImageName(image=""), **kwargs
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert client_response.content_type == "application/json"
    assert client_response.headers["Docker-Distribution-Api-Version"] == "registry/2.0"


@pytest.mark.online
async def test_get_version(
    docker_registry_client_async: DockerRegistryClientAsync, **kwargs
):
    """Test that the endpoint implements Docker Registry API v2."""
    response = await docker_registry_client_async.get_version(
        ImageName(image=""), **kwargs
    )
    assert all(x in response for x in ["client_response", "result"])
    assert response["result"]


@pytest.mark.online
async def test__head_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Checking blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    client_response = await docker_registry_client_async._head_blob(
        manifest_data["image_name"], config_digest, **kwargs
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
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_remote, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Checking blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    response = await docker_registry_client_async.head_blob(
        manifest_data["image_name"], config_digest, **kwargs
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
        manifest_data["image_name"], config_digest, **kwargs
    )
    assert all(x in response for x in ["client_response", "digest", "result"])
    assert not response["result"]


@pytest.mark.online
async def test__head_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image_remote).keys()
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        client_response = await docker_registry_client_async._head_manifest(
            image_name, **kwargs
        )
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
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_remote: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image_remote).keys()
    if "protocol" in known_good_image_remote:
        kwargs["protocol"] = known_good_image_remote["protocol"]

    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        response = await docker_registry_client_async.head_manifest(
            image_name, **kwargs
        )
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
            response = await docker_registry_client_async.head_manifest(
                image_name, **kwargs
            )
            assert all(x in response for x in ["client_response", "digest", "result"])
            assert not response["result"]


@pytest.mark.online_modification
async def test__patch_blob_upload_chunked(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the status of image blob uploads (chunked) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    chunk_size = 5
    upload_length = 0
    location = response["location"]
    for offset in range(0, len(known_binary_data["data"]), chunk_size):
        chunk = known_binary_data["data"][offset : offset + chunk_size]
        client_response = await docker_registry_client_async._patch_blob_upload(
            location, chunk, offset=offset, **kwargs
        )
        upload_length += len(chunk)
        assert client_response
        assert (
            client_response.status == HTTPStatus.ACCEPTED
        )  # rad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:178)
        assert client_response.headers["Content-Length"] == "0"
        assert client_response.headers["Docker-Upload-UUID"]
        assert client_response.headers["Location"]
        assert client_response.headers["Range"] == f"0-{upload_length - 1}"
        location = client_response.headers["Location"]


@pytest.mark.online_modification
async def test__patch_blob_upload_stream(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    client_response = await docker_registry_client_async._patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )


@pytest.mark.online_modification
async def test_patch_blob_upload_from_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

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
            **kwargs,
        )
    assert all(x in response for x in ["client_response", "digest", "size"])
    digest = response["digest"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )

    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.patch_blob_upload_from_disk(
            response["location"], file, **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

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
            **kwargs,
        )
    assert all(x in response for x in ["client_response", "digest", "size"])
    digest = response["digest"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )

    with path.open("r+b") as file:
        response = await docker_registry_client_async.patch_blob_upload_from_disk(
            response["location"], file, file_is_async=False, **kwargs
        )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )
    assert response["digest"] == digest


@pytest.mark.skip(
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__post_blob_monolithic(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating monolithic blob upload: %s ...",
        manifest_data["image_name"].resolve_image(),
    )
    client_response = await docker_registry_client_async._post_blob(
        manifest_data["image_name"],
        data=known_binary_data["data"],
        digest=known_binary_data["digest"],
        **kwargs,
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating resumable blob upload: %s ...",
        manifest_data["image_name"].resolve_image(),
    )
    client_response = await docker_registry_client_async._post_blob(
        manifest_data["image_name"], **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the blobs can be mounted from other repositories."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    layer = manifest_data["manifest_json"]["layers"][0]
    layer_digest = FormattedSHA256.parse(layer["digest"])

    destination = manifest_data["image_name"].clone()
    destination.image += "copy"

    LOGGER.debug(
        "Initiating blob mount: %s/%s -> %s ...",
        manifest_data["image_name"].resolve_image(),
        layer_digest,
        destination.resolve_image(),
    )
    client_response = await docker_registry_client_async._post_blob(
        destination, source=manifest_data["image_name"], digest=layer_digest, **kwargs
    )
    assert client_response
    assert (
        client_response.status == HTTPStatus.ACCEPTED
    )  # Bad docs: should be HTTPStatus.CREATED (code check: registry/handlers/blobupload.go:100)
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test_post_blob(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )


@pytest.mark.online_modification
async def test__put_blob_upload(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )

    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Sending blob upload data ...")
    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload ...")
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
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
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_post(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload with data: %s ...",
        manifest_data["image_name"].resolve_image(),
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], data=known_binary_data["data"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload ...")
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    LOGGER.debug("Completing blob upload (with data) ...")
    client_response = await docker_registry_client_async._put_blob_upload(
        response["location"],
        known_binary_data["digest"],
        data=known_binary_data["data"],
        **kwargs,
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug(
        "Initiating blob upload: %s ...", manifest_data["image_name"].resolve_image()
    )
    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    response = await docker_registry_client_async.patch_blob_upload(
        response["location"], known_binary_data["data"], **kwargs
    )

    response = await docker_registry_client_async.put_blob_upload(
        response["location"], known_binary_data["digest"], **kwargs
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
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            **kwargs,
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.put_blob_upload_from_disk(
            response["location"], config_digest, file, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest", "location"])
    assert response["digest"] == config_digest


@pytest.mark.online_modification
async def test_put_blob_upload_from_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async, known_good_image_local, **kwargs
    )
    config = manifest_data["manifest_json"]["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    config_digest = config["digest"]
    LOGGER.debug(
        "Retrieving blob: %s/%s ...",
        manifest_data["image_name"].resolve_image(),
        config_digest,
    )
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_blob_to_disk(
            manifest_data["image_name"],
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
            **kwargs,
        )
    assert response
    assert all(x in response for x in ["client_response", "digest", "size"])

    assert response["digest"] == config["digest"]
    assert response["size"] == int(
        response["client_response"].headers["Content-Length"]
    )

    response = await docker_registry_client_async.post_blob(
        manifest_data["image_name"], **kwargs
    )
    assert all(
        x in response
        for x in ["client_response", "docker_upload_uuid", "location", "range"]
    )

    with path.open("r+b") as file:
        response = await docker_registry_client_async.put_blob_upload_from_disk(
            response["location"], config_digest, file, file_is_async=False, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest", "location"])
    assert response["digest"] == config_digest


@pytest.mark.online_modification
async def test__put_manifest(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image_local)
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type, **kwargs
        )
        assert all(x in response for x in ["client_response", "manifest"])

        client_response = await docker_registry_client_async._put_manifest(
            image_name,
            response["manifest"].get_bytes(),
            media_type=response["manifest"].get_media_type(),
            **kwargs,
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
    known_good_image_local: TypingKnownGoodImage,
    **kwargs,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image_local)
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async.get_manifest(
            image_name, accept=media_type, **kwargs
        )
        assert all(x in response for x in ["client_response", "manifest"])

        manifest = response["manifest"]
        assert manifest

        # Put the manifest as is ...
        response = await docker_registry_client_async.put_manifest(
            image_name, manifest, **kwargs
        )
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
        response = await docker_registry_client_async.put_manifest(
            image_name, manifest, **kwargs
        )
        assert all(x in response for x in ["client_response", "digest"])

        assert response["digest"] == manifest.get_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_async(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image_local["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image_local['image']}@{digest}")
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest", "size"])

    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async.put_manifest_from_disk(
            image_name, file, media_type=media_type, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest"])
    assert response["digest"] == image_name.resolve_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_sync(
    docker_registry_client_async: DockerRegistryClientAsync,
    known_good_image_local: TypingKnownGoodImage,
    tmp_path: Path,
    **kwargs,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image_local["digests"][media_type]
    image_name = ImageName.parse(f"{known_good_image_local['image']}@{digest}")
    if "protocol" in known_good_image_local:
        kwargs["protocol"] = known_good_image_local["protocol"]

    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    with path.open("w+b") as file:
        response = await docker_registry_client_async.get_manifest_to_disk(
            image_name, file, file_is_async=False, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest", "size"])

    with path.open("r+b") as file:
        response = await docker_registry_client_async.put_manifest_from_disk(
            image_name, file, file_is_async=False, media_type=media_type, **kwargs
        )
    assert all(x in response for x in ["client_response", "digest"])
    assert response["digest"] == image_name.resolve_digest()


# TODO: Total image pull (with exists() checks)
# TODO: Total image push
