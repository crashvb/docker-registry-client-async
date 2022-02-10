#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""HashingGenerator tests."""

from pathlib import Path
from typing import Generator, NamedTuple

import aiofiles
import pytest

from docker_registry_client_async import (
    DockerMediaTypes,
    MediaTypes,
    OCIMediaTypes,
)
from docker_registry_client_async.hashinggenerator import HashingGenerator

from .testutils import get_test_data_path, hash_file

pytestmark = [pytest.mark.asyncio]


class TypingHashingGenerator(NamedTuple):
    # pylint: disable=missing-class-docstring
    hashing_generator: HashingGenerator
    path: Path


@pytest.fixture(
    params=[
        DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2,
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED,
        DockerMediaTypes.DISTRIBUTION_MANIFEST_V2,
        MediaTypes.APPLICATION_JSON,
        OCIMediaTypes.IMAGE_INDEX_V1,
        OCIMediaTypes.IMAGE_MANIFEST_V1,
    ]
)
def manifest_name(request) -> Path:
    """Provides raw manifest names."""
    name = f"manifest.{request.param.replace('application/', '').replace('+', '.').replace('prettyjws', 'json')}"
    return get_test_data_path(request, name)


@pytest.fixture()
async def hashing_generator_async(
    manifest_name: Path,
) -> Generator[TypingHashingGenerator, None, None]:
    """Provides hashing generator instance and associated data."""
    async with aiofiles.open(manifest_name, mode="r+b") as file:
        yield TypingHashingGenerator(
            hashing_generator=HashingGenerator(file), path=manifest_name
        )


@pytest.fixture()
def hashing_generator_sync(
    manifest_name: Path,
) -> Generator[TypingHashingGenerator, None, None]:
    """Provides hashing generator instance and associated data."""
    with manifest_name.open("r+b") as file:
        yield TypingHashingGenerator(
            hashing_generator=HashingGenerator(file, file_is_async=False),
            path=manifest_name,
        )


async def test_get_digest_async(
    hashing_generator_async: TypingHashingGenerator,
):
    """Test digest value calculation (async)."""
    async for _ in hashing_generator_async.hashing_generator:
        pass
    digest = await hash_file(hashing_generator_async.path)
    assert hashing_generator_async.hashing_generator.get_digest() == digest


async def test_get_digest_sync(
    hashing_generator_sync: TypingHashingGenerator,
):
    """Test digest value calculation (sync)."""
    async for _ in hashing_generator_sync.hashing_generator:
        pass
    digest = await hash_file(hashing_generator_sync.path)
    assert hashing_generator_sync.hashing_generator.get_digest() == digest
