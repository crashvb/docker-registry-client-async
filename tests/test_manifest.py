#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

from typing import TypedDict

import pytest

from docker_registry_client_async import (
    DockerMediaTypes,
    FormattedSHA256,
    Manifest,
    MediaTypes,
    OCIMediaTypes,
)

from .testutils import get_test_data


class TypingManifestData(TypedDict):
    # pylint: disable=missing-class-docstring
    bytes: bytes
    manifest: Manifest
    media_type: str


class TypingRawManifest(TypedDict):
    # pylint: disable=missing-class-docstring
    bytes: bytes
    media_type: str


@pytest.fixture()
def manifest_data(raw_manifest: TypingRawManifest) -> TypingManifestData:
    """Provides Manifest instance and associated data."""
    manifest = Manifest(raw_manifest["bytes"], media_type=raw_manifest["media_type"])
    return {
        "bytes": raw_manifest["bytes"],
        "manifest": manifest,
        "media_type": raw_manifest["media_type"],
    }


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
def raw_manifest(request) -> TypingRawManifest:
    """Provides raw manifest values and associated data."""
    name = f"manifest.{request.param.replace('application/', '').replace('+', '.').replace('prettyjws', 'json')}"
    return {
        "bytes": get_test_data(request, __name__, name),
        "media_type": request.param,
    }


def test___init__(manifest_data: TypingManifestData):
    """Test that an image manifest can be instantiated."""
    manifest = manifest_data["manifest"]
    assert manifest.bytes == manifest_data["bytes"]
    assert manifest.json
    assert manifest.media_type


def test___bytes__(manifest_data: TypingManifestData):
    """Test __bytes__ pass-through for different variants."""
    assert bytes(manifest_data["manifest"]) == manifest_data["bytes"]


def test___str__(manifest_data: TypingManifestData):
    """Test __str__ pass-through for different variants."""
    string = str(manifest_data["manifest"])
    assert string
    assert "None" not in string


def test__detect_media_type(raw_manifest: TypingRawManifest):
    """Test that media types can be detected."""
    manifest = Manifest(raw_manifest["bytes"])
    assert manifest.media_type == raw_manifest["media_type"]


def test_get_bytes(manifest_data: TypingManifestData):
    """Test raw image manifest retrieval."""
    assert manifest_data["manifest"].get_bytes() == manifest_data["bytes"]


def test_get_digest(manifest_data: TypingManifestData):
    """Test raw image manifest retrieval."""
    digest = manifest_data["manifest"].get_digest()
    assert digest == FormattedSHA256.calculate(manifest_data["bytes"])


def test_get_json(manifest_data: TypingManifestData):
    """Test image manifest retrieval."""
    assert manifest_data["manifest"].get_json()


def test_get_media_type(manifest_data: TypingManifestData):
    """Test manifest media type retrieval."""
    media_type = manifest_data["manifest"].get_media_type()
    assert media_type == manifest_data["media_type"]
