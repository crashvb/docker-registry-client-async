#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name,too-many-lines

"""DockerRegistryClientAsync tests."""

import asyncio
import hashlib
import json
import logging

from http import HTTPStatus
from pathlib import Path
from ssl import create_default_context

import aiofiles
import pytest

from aiohttp.helpers import BasicAuth
from pytest_docker_registry_fixtures import (
    DockerRegistrySecure,
)
from pytest_docker_squid_fixtures import SquidSecure

from docker_registry_client_async import (
    DockerMediaTypes,
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
    MediaTypes,
)

from .test_dockerregistryclientasync import (
    credentials_store_path,  # Needed for pytest
    get_identifier_map,
    get_manifest_json,
    get_test_data,
    known_binary_data,  # Needed for pytest
    pytestmark as dockerregistryclientasync_pytestmark,
    replicate_manifest_lists,  # Needed for pytest
    TypingGetBinaryData,
    TypingKnownGoodImage,
)
from .testutils import hash_file

pytestmark = dockerregistryclientasync_pytestmark

LOGGER = logging.getLogger(__name__)

# Bug Fix: https://github.com/crashvb/docker-registry-client-async/issues/24
#
# Right now this is known to leave a nasty "Fatal error on SSL transport" error
# at the end of the test execution; however, without this we cannot test using
# a TLS-in-TLS proxy ...
setattr(asyncio.sslproto._SSLProtocolTransport, "_start_tls_compatible", True)


@pytest.fixture
# HACK: Invoke replicate_manifest_list fixture to tell PDRF about the manifest lists we use for testing ...
async def docker_registry_client_async_proxy(
    credentials_store_path: Path,
    docker_registry_secure: DockerRegistrySecure,
    replicate_manifest_lists,
    squid_secure: SquidSecure,
) -> DockerRegistryClientAsync:
    # pylint: disable=unused-argument
    """Provides a DockerRegistryClientAsync instance."""
    # Do not use caching; get a new instance for each test
    ssl_context = create_default_context(
        cadata=squid_secure.certs.ca_certificate.read_text("utf-8")
        + docker_registry_secure.certs.ca_certificate.read_text("utf-8")
    )
    async with DockerRegistryClientAsync(
        credentials_store=credentials_store_path, ssl=ssl_context
    ) as docker_registry_client_async:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        for name in [
            docker_registry_secure.endpoint,
            docker_registry_secure.endpoint_name,
        ]:
            await docker_registry_client_async.add_credentials(
                credentials=credentials, endpoint=name
            )
        docker_registry_client_async.proxies[
            "https"
        ] = f"https://{squid_secure.endpoint}/"
        docker_registry_client_async.proxy_auth = BasicAuth(
            login=squid_secure.username, password=squid_secure.password
        )

        yield docker_registry_client_async


@pytest.fixture(scope="session")
# Required for asynchronous, session-scoped, fixtures
def event_loop():
    """Create an instance of the default event loop once for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(params=get_test_data())
def known_good_image_proxy(
    docker_registry_secure: DockerRegistrySecure, request
) -> TypingKnownGoodImage:
    """Provides 'known good' metadata for a local image that can be modified."""
    image_name = ImageName.parse(request.param.image)
    # Because the squid fixture is also running inside of docker-compose, it will be issued separate network stacks and
    # trying to resolve the registry (HTTP CONNECT) using 127.0.0.1 as the endpoint address will not work. Instead, use
    # the docker-compose default network, and the internal service port.
    image_name.endpoint = docker_registry_secure.endpoint_name
    manifest_digest = request.param.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    return TypingKnownGoodImage(
        digests=request.param.digests,
        image=str(image_name),
        image_name=ImageName.parse(
            f"{str(image_name)}:{request.param.tag}@{manifest_digest}"
        ),
        tag=request.param.tag,
    )


@pytest.mark.online_deletion
async def test__delete_blob(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )
    await docker_registry_client_async_proxy.put_blob_upload(
        response.location, known_binary_data.digest
    )

    LOGGER.debug("Deleting blob: %s ...", known_binary_data.digest)
    client_response = await docker_registry_client_async_proxy._delete_blob(
        manifest_data.image_name, known_binary_data.digest
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED
    assert client_response.headers["Content-Length"] == "0"
    # Bad docs (code check: registry/handlers/blob.go:97)
    # assert client_response.headers["Docker-Content-Digest"] == known_binary_data.digest


@pytest.mark.online_deletion
async def test_delete_blob(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )
    await docker_registry_client_async_proxy.put_blob_upload(
        response.location, known_binary_data.digest
    )

    LOGGER.debug("Deleting blob: %s ...", known_binary_data.digest)
    response = await docker_registry_client_async_proxy.delete_blob(
        manifest_data.image_name, known_binary_data.digest
    )
    assert response.client_response
    assert response.result


@pytest.mark.online_deletion
async def test__delete_blob_upload(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    LOGGER.debug("Deleting blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._delete_blob_upload(
        response.location
    )
    assert client_response
    assert client_response.status == HTTPStatus.NO_CONTENT
    # assert client_response.headers["Content-Length"] == "0"  # Bad docs


@pytest.mark.online_deletion
async def test_delete_blob_upload(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )

    # Don't complete the blob upload (by sending a PUT), and delete it ...
    response = await docker_registry_client_async_proxy.delete_blob_upload(
        response.location
    )
    assert response.client_response
    assert response.result


@pytest.mark.online_deletion
async def test__delete_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )

    # Modify the manifest ...
    manifest = manifest_data.manifest
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data.image_name
    image_name.digest = manifest.get_digest()
    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
    response = await docker_registry_client_async_proxy.put_manifest(
        image_name, manifest
    )
    assert response.digest == manifest.get_digest()

    # ... then delete it ...
    LOGGER.debug("Deleting manifest: %s ...", image_name)
    client_response = await docker_registry_client_async_proxy._delete_manifest(
        image_name
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED


@pytest.mark.online_deletion
async def test_delete_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )

    # Modify the manifest ...
    manifest = manifest_data.manifest
    digest_old = manifest.get_digest()
    manifest.json["x"] = 1
    manifest._set_json(manifest.get_json())
    assert manifest.get_digest() != digest_old

    # ... and stage it for deletion ...
    image_name = manifest_data.image_name
    image_name.digest = manifest.get_digest()
    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
    response = await docker_registry_client_async_proxy.put_manifest(
        image_name, manifest
    )
    assert response.digest == manifest.get_digest()

    # ... then delete it ...
    LOGGER.debug("Deleting manifest: %s ...", image_name)
    response = await docker_registry_client_async_proxy.delete_manifest(image_name)
    assert response.client_response
    assert response.result


@pytest.mark.online
async def test__get_blob_config(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    client_response = await docker_registry_client_async_proxy._get_blob(
        manifest_data.image_name, config_digest, accept=config["mediaType"]
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    layer = manifest_data.manifest_json["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    layer_digest = layer["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, layer_digest)
    client_response = await docker_registry_client_async_proxy._get_blob(
        manifest_data.image_name, layer_digest, accept=layer["mediaType"]
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image blobs (layers) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    layer = manifest_data.manifest_json["layers"][0]
    assert all(x in layer for x in ["digest", "mediaType", "size"])

    layer_digest = layer["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, layer_digest)
    response = await docker_registry_client_async_proxy.get_blob(
        manifest_data.image_name, layer_digest, accept=layer["mediaType"]
    )
    assert response.blob
    assert response.client_response


@pytest.mark.online
async def test_get_blob_to_disk_async(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image blobs (image configurations) can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert response
    assert response.client_response
    assert response.digest == config["digest"]
    assert response.size == int(response.client_response.headers["Content-Length"])

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == config["digest"]


@pytest.mark.online
async def test_get_blob_to_disk_sync(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image blobs (image configurations) can be retrieved to disk synchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
        )
    assert response
    assert response.client_response
    assert response.digest == config["digest"]
    assert response.size == int(response.client_response.headers["Content-Length"])

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == config["digest"]


@pytest.mark.online_modification
async def test__get_blob_upload(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Retrieving blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._get_blob_upload(
        response.location
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Retrieving blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.get_blob_upload(
        response.location
    )
    assert response.client_response
    assert response.location
    assert response.range == "0-0"


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test__get_catalog(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image catalog can be retrieved."""
    LOGGER.debug("Retrieving catalog ...")
    client_response = await docker_registry_client_async_proxy._get_catalog(
        known_good_image_proxy.image_name
    )
    assert client_response
    assert client_response.status == HTTPStatus.OK

    catalog = json.loads(await client_response.text())
    assert "repositories" in catalog
    assert known_good_image_proxy.image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
# Note: Catalog is disabled for Docker Hub: https://forums.docker.com/t/registry-v2-catalog/45368
async def test_get_catalog(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image catalog can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_proxy.image}:{known_good_image_proxy.tag}"
    )
    LOGGER.debug("Retrieving catalog ...")
    response = await docker_registry_client_async_proxy.get_catalog(image_name)
    assert response.catalog
    assert response.client_response

    catalog = response.catalog
    assert "repositories" in catalog
    assert image_name.resolve_image() in catalog["repositories"]


@pytest.mark.online
async def test__get_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image_proxy)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        client_response = await docker_registry_client_async_proxy._get_manifest(
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
            LOGGER.debug("Skipping digest check for: %s (%s)", image_name, media_type)

        assert json.loads(await client_response.text())
        assert client_response.headers["Content-Type"] == media_type


@pytest.mark.online
async def test_get_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be retrieved."""
    identifier_map = get_identifier_map(known_good_image_proxy)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async_proxy.get_manifest(
            image_name, accept=media_type
        )
        assert response.client_response
        assert response.manifest

        manifest = response.manifest
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
    async with DockerRegistryClientAsync() as docker_registry_client_async_proxy:
        image_name = ImageName.parse("python")
        media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async_proxy.get_manifest(
            image_name, accept=media_type
        )
        assert response.client_response
        assert response.manifest


@pytest.mark.online
async def test_get_manifest_to_disk_async(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    digest = known_good_image_proxy.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    image_name = ImageName.parse(f"{known_good_image_proxy.image}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_manifest_to_disk(
            image_name, file
        )
    assert response
    assert response.client_response
    assert response.digest == image_name.resolve_digest()
    assert response.size == int(response.client_response.headers["Content-Length"])

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == image_name.resolve_digest()


@pytest.mark.online
async def test_get_manifest_to_disk_sync(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk synchronously."""
    digest = known_good_image_proxy.digests[DockerMediaTypes.DISTRIBUTION_MANIFEST_V2]
    image_name = ImageName.parse(f"{known_good_image_proxy.image}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest.json")
    with path.open("w+b") as file:
        response = await docker_registry_client_async_proxy.get_manifest_to_disk(
            image_name, file, file_is_async=False
        )
    assert response
    assert response.client_response
    assert response.digest == image_name.resolve_digest()
    assert response.size == int(response.client_response.headers["Content-Length"])

    LOGGER.debug("Verifying digest of written file ...")
    assert await hash_file(path) == image_name.resolve_digest()


@pytest.mark.online
async def test__get_tags(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_proxy.image}:{known_good_image_proxy.tag}"
    )
    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    client_response = await docker_registry_client_async_proxy._get_tags(image_name)
    assert client_response
    assert client_response.status == HTTPStatus.OK

    tags = json.loads(await client_response.text())
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test_get_tag_list(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_proxy.image}:{known_good_image_proxy.tag}"
    )
    LOGGER.debug("Retrieving tag list for: %s ...", image_name)
    response = await docker_registry_client_async_proxy.get_tag_list(image_name)
    assert response.client_response
    assert response.tags

    result = False
    for entry in response.tags:
        if entry.resolve_tag() == image_name.resolve_tag():
            result = True
            break
    assert result


@pytest.mark.online
async def test_get_tags(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image tags can be retrieved."""
    image_name = ImageName.parse(
        f"{known_good_image_proxy.image}:{known_good_image_proxy.tag}"
    )
    LOGGER.debug("Retrieving tags for: %s ...", image_name)
    response = await docker_registry_client_async_proxy.get_tags(image_name)
    assert response.client_response
    assert response.tags

    tags = response.tags
    assert tags["name"] == image_name.resolve_image()
    assert "tags" in tags
    assert image_name.resolve_tag() in tags["tags"]


@pytest.mark.online
async def test__get_version(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the endpoint implements Docker Registry API v2."""
    LOGGER.debug(
        "Retrieving version from %s ...", known_good_image_proxy.image_name.endpoint
    )
    client_response = await docker_registry_client_async_proxy._get_version(
        known_good_image_proxy.image_name
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
    async with DockerRegistryClientAsync() as docker_registry_client_async_proxy:
        LOGGER.debug("Retrieving version from %s ...", image_name.resolve_endpoint())
        client_response = await docker_registry_client_async_proxy._get_version(
            image_name
        )
    assert client_response
    assert client_response.status == HTTPStatus.OK
    assert client_response.content_type == "application/json"
    assert client_response.headers["Docker-Distribution-Api-Version"] == "registry/2.0"


@pytest.mark.online
async def test_get_version(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the endpoint implements Docker Registry API v2."""
    LOGGER.debug(
        "Retrieving version from %s ...", known_good_image_proxy.image_name.endpoint
    )
    response = await docker_registry_client_async_proxy.get_version(
        known_good_image_proxy.image_name
    )
    assert response.client_response
    assert response.result


@pytest.mark.online
async def test__head_blob(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Checking blob: %s/%s ...", manifest_data.image_name, config_digest)
    client_response = await docker_registry_client_async_proxy._head_blob(
        manifest_data.image_name, config_digest
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image blobs (image configurations) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Checking blob: %s/%s ...", manifest_data.image_name, config_digest)
    response = await docker_registry_client_async_proxy.head_blob(
        manifest_data.image_name, config_digest
    )
    assert response.client_response
    # TODO: Docker-Content-Digest is returned by a local v2 registry, but not Docker Hub ?!?
    # assert response.digest == config_digest
    assert response.result

    # Negative test
    sha256_old = config_digest
    config_digest = config_digest.replace("1", "2")
    assert config_digest != sha256_old
    response = await docker_registry_client_async_proxy.head_blob(
        manifest_data.image_name, config_digest
    )
    assert response.client_response
    assert not response.digest
    assert not response.result


@pytest.mark.online
async def test__head_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image_proxy).keys()
    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        client_response = await docker_registry_client_async_proxy._head_manifest(
            image_name
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests existence can be checked."""
    image_names = get_identifier_map(known_good_image_proxy).keys()
    for image_name in image_names:
        LOGGER.debug("Checking manifest for: %s ...", image_name)
        response = await docker_registry_client_async_proxy.head_manifest(image_name)
        assert response.client_response
        assert response.digest
        assert response.result

        if image_name.digest:
            assert response.digest == image_name.resolve_digest()
        else:
            LOGGER.debug("Skipping digest check for: %s", image_name)
        assert response.result

        # Negative test
        if image_name.digest:
            sha256_old = image_name.digest.sha256
            image_name.digest = FormattedSHA256(
                image_name.digest.sha256.replace("1", "2")
            )
            assert image_name.digest.sha256 != sha256_old
            response = await docker_registry_client_async_proxy.head_manifest(
                image_name
            )
            assert response.client_response
            assert not response.digest
            assert not response.result


@pytest.mark.online_modification
async def test__patch_blob_upload_chunked(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (chunked) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    chunk_size = 5
    upload_length = 0
    location = response.location
    LOGGER.debug("Patching blob upload: %s ...", response.location)
    for offset in range(0, len(known_binary_data.data), chunk_size):
        chunk = known_binary_data.data[offset : offset + chunk_size]
        client_response = await docker_registry_client_async_proxy._patch_blob_upload(
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._patch_blob_upload(
        response.location, known_binary_data.data
    )
    assert client_response
    assert (
        client_response.status == HTTPStatus.ACCEPTED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:178)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == f"0-{len(known_binary_data.data) - 1}"


@pytest.mark.online_modification
async def test_patch_blob_upload_stream(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the status of image blob uploads (stream) can be retrieved."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range


@pytest.mark.online_modification
async def test_patch_blob_upload_from_disk_async(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert response.client_response
    digest = response.digest
    assert response.size

    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async_proxy.patch_blob_upload_from_disk(
            response.location, file
        )
    assert response.client_response
    assert response.digest == digest
    assert response.docker_upload_uuid
    assert response.location
    assert response.range


@pytest.mark.online_modification
async def test_patch_blob_upload_from_disk_sync(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that image blob uploads can be retrieved from disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    with path.open(mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            file_is_async=False,
            accept=config["mediaType"],
        )
    assert response.client_response
    assert response.digest
    assert response.size
    digest = response.digest

    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    with path.open("r+b") as file:
        response = await docker_registry_client_async_proxy.patch_blob_upload_from_disk(
            response.location, file, file_is_async=False
        )
    assert response.client_response
    assert response.digest == digest
    assert response.docker_upload_uuid
    assert response.location
    assert response.range


@pytest.mark.skip(
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke"
    "blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__post_blob_monolithic(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating monolithic blob upload: %s ...", manifest_data.image_name)
    client_response = await docker_registry_client_async_proxy._post_blob(
        manifest_data.image_name,
        data=known_binary_data.data,
        digest=known_binary_data.digest,
    )
    assert client_response
    assert client_response.status == HTTPStatus.CREATED
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test__post_blob_resumable(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating resumable blob upload: %s ...", manifest_data.image_name)
    client_response = await docker_registry_client_async_proxy._post_blob(
        manifest_data.image_name
    )
    assert client_response
    assert client_response.status == HTTPStatus.ACCEPTED
    assert int(client_response.headers["Content-Length"]) == 0
    assert client_response.headers["Docker-Upload-UUID"]
    assert client_response.headers["Location"]
    assert client_response.headers["Range"] == "0-0"


@pytest.mark.online_modification
async def test__post_blob_mount(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the blobs can be mounted from other repositories."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )

    layer = manifest_data.manifest_json["layers"][0]
    layer_digest = FormattedSHA256.parse(layer["digest"])

    destination = manifest_data.image_name.clone()
    destination.image += __name__

    LOGGER.debug(
        "Initiating blob mount: %s/%s -> %s ...",
        manifest_data.image_name,
        layer_digest,
        destination,
    )
    client_response = await docker_registry_client_async_proxy._post_blob(
        destination, source=manifest_data.image_name, digest=layer_digest
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the blobs uploads can be initiated."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range


@pytest.mark.online_modification
async def test__put_blob_upload(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.range

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._put_blob_upload(
        response.location, known_binary_data.digest
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Content-Digest"] == known_binary_data.digest
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_patch(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._put_blob_upload(
        response.location, known_binary_data.digest
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Content-Digest"] == known_binary_data.digest
    assert client_response.headers["Location"]


@pytest.mark.skip(
    "Code check shows that registry/handlers/blobupload.go::StartBlobUpload does not invoke"
    "blobUploadHandler.copyFullPayload(); so this documented scenario is invalid =/"
)
@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_post(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload (with data): %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name, data=known_binary_data.data
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._put_blob_upload(
        response.location, known_binary_data.digest
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Content-Digest"] == known_binary_data.digest
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test__put_blob_upload_monolithic_data_in_put(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed monolithically."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Completing blob upload (with data): %s ...", response.location)
    client_response = await docker_registry_client_async_proxy._put_blob_upload(
        response.location,
        known_binary_data.digest,
        data=known_binary_data.data,
    )

    assert client_response
    assert (
        client_response.status == HTTPStatus.CREATED
    )  # Bad docs: should be HTTPStatus.NO_CONTENT (code check: registry/handlers/blobupload.go:373)
    assert client_response.headers["Content-Length"] == "0"
    assert client_response.headers["Docker-Content-Digest"] == known_binary_data.digest
    assert client_response.headers["Location"]


@pytest.mark.online_modification
async def test_put_blob_upload(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_binary_data: TypingGetBinaryData,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that an image blob upload can be completed."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Patching blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.patch_blob_upload(
        response.location, known_binary_data.data
    )

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    response = await docker_registry_client_async_proxy.put_blob_upload(
        response.location, known_binary_data.digest
    )
    assert response.client_response
    assert response.digest
    assert response.location
    assert response.client_response.headers["Content-Length"] == "0"
    assert (
        response.client_response.headers["Docker-Content-Digest"]
        == known_binary_data.digest
    )
    assert response.client_response.headers["Location"]


@pytest.mark.online_modification
async def test_put_blob_upload_from_disk_async(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            accept=config["mediaType"],
        )
    assert response
    assert response.client_response
    assert response.digest == config["digest"]
    assert response.size == int(response.client_response.headers["Content-Length"])

    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async_proxy.put_blob_upload_from_disk(
            response.location, config_digest, file
        )
    assert response.client_response
    assert response.digest == config_digest
    assert response.location


@pytest.mark.online_modification
async def test_put_blob_upload_from_disk_sync(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    manifest_data = await get_manifest_json(
        docker_registry_client_async_proxy, known_good_image_proxy
    )
    config = manifest_data.manifest_json["config"]
    assert all(x in config for x in ["digest", "mediaType", "size"])

    config_digest = config["digest"]
    LOGGER.debug("Retrieving blob: %s/%s ...", manifest_data.image_name, config_digest)
    path = tmp_path.joinpath("blob")
    with path.open("w+b") as file:
        response = await docker_registry_client_async_proxy.get_blob_to_disk(
            manifest_data.image_name,
            config_digest,
            file,
            accept=config["mediaType"],
            file_is_async=False,
        )
    assert response
    assert response.client_response
    assert response.digest == config["digest"]
    assert response.size == int(response.client_response.headers["Content-Length"])

    manifest_data.image_name.image += __name__

    LOGGER.debug("Initiating blob upload: %s ...", manifest_data.image_name)
    response = await docker_registry_client_async_proxy.post_blob(
        manifest_data.image_name
    )
    assert response.client_response
    assert response.docker_upload_uuid
    assert response.location
    assert response.range

    LOGGER.debug("Completing blob upload: %s ...", response.location)
    with path.open("r+b") as file:
        response = await docker_registry_client_async_proxy.put_blob_upload_from_disk(
            response.location, config_digest, file, file_is_async=False
        )
    assert response.client_response
    assert response.digest == config_digest
    assert response.location


@pytest.mark.online_modification
async def test__put_manifest(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image_proxy)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async_proxy.get_manifest(
            image_name, accept=media_type
        )
        assert response.client_response
        assert response.manifest

        if image_name.tag:
            image_name.tag += __name__
        LOGGER.debug(
            "Storing manifest: %s (%s) ...",
            image_name,
            response.manifest.get_digest(),
        )
        client_response = await docker_registry_client_async_proxy._put_manifest(
            image_name,
            response.manifest.get_bytes(),
            media_type=response.manifest.get_media_type(),
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
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
):
    """Test that the image manifests can be stored."""
    identifier_map = get_identifier_map(known_good_image_proxy)
    for image_name, media_type in identifier_map.items():
        LOGGER.debug("Retrieving manifest for: %s (%s) ...", image_name, media_type)
        response = await docker_registry_client_async_proxy.get_manifest(
            image_name, accept=media_type
        )
        assert response.client_response
        assert response.manifest

        manifest = response.manifest
        assert manifest

        # Put the manifest as is ...
        if image_name.tag:
            image_name.tag += __name__
        LOGGER.debug("Storing manifest: %s (%s) ...", image_name, manifest.get_digest())
        response = await docker_registry_client_async_proxy.put_manifest(
            image_name, manifest
        )
        assert response.client_response
        assert response.digest

        if image_name.digest:
            assert response.digest == image_name.resolve_digest()
        assert response.digest == manifest.get_digest()

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
        response = await docker_registry_client_async_proxy.put_manifest(
            image_name, manifest
        )
        assert response.client_response
        assert response.digest == manifest.get_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_async(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image_proxy.digests[media_type]
    image_name = ImageName.parse(f"{known_good_image_proxy.image}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    async with aiofiles.open(path, mode="w+b") as file:
        response = await docker_registry_client_async_proxy.get_manifest_to_disk(
            image_name, file
        )
    assert response.client_response
    assert response.digest
    assert response.size

    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s ...", image_name)
    async with aiofiles.open(path, mode="r+b") as file:
        response = await docker_registry_client_async_proxy.put_manifest_from_disk(
            image_name, file, media_type=media_type
        )
    assert response.client_response
    assert response.digest == image_name.resolve_digest()


@pytest.mark.online_modification
async def test_put_manifest_from_disk_sync(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    known_good_image_proxy: TypingKnownGoodImage,
    tmp_path: Path,
):
    """Test that the image manifests can be retrieved to disk asynchronously."""
    media_type = DockerMediaTypes.DISTRIBUTION_MANIFEST_V2
    digest = known_good_image_proxy.digests[media_type]
    image_name = ImageName.parse(f"{known_good_image_proxy.image}@{digest}")
    LOGGER.debug("Retrieving manifest for: %s ...", image_name)
    path = tmp_path.joinpath("manifest")
    with path.open("w+b") as file:
        response = await docker_registry_client_async_proxy.get_manifest_to_disk(
            image_name, file, file_is_async=False
        )
    assert response.client_response
    assert response.digest
    assert response.size

    if image_name.tag:
        image_name.tag += __name__
    LOGGER.debug("Storing manifest: %s ...", image_name)
    with path.open("r+b") as file:
        response = await docker_registry_client_async_proxy.put_manifest_from_disk(
            image_name, file, file_is_async=False, media_type=media_type
        )
    assert response.client_response
    assert response.digest == image_name.resolve_digest()


# TODO: Total image pull (with exists() checks)
# TODO: Total image push
