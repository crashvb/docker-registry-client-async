#!/usr/bin/env python

# pylint: disable=redefined-outer-name,protected-access

"""ImageName tests."""

from typing import Dict

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName


def get_test_data() -> Dict:
    """Dynamically initializes test data."""
    for endpoint in ["endpoint.io", "endpoint:port", None]:
        for image in ["image", "ns0/image", "ns0/ns1/image", "ns0/ns1/ns2/image"]:
            for tag in ["tag", None]:
                for digest in [FormattedSHA256.calculate(b""), None]:
                    # Construct a complex string ...
                    string = image
                    if tag:
                        string = f"{string}:{tag}"
                    if digest:
                        string = f"{string}@{digest}"
                    if endpoint:
                        string = f"{endpoint}/{string}"
                    yield {
                        "digest": digest,
                        "endpoint": endpoint,
                        "image": image,
                        "object": ImageName.parse(string),
                        "string": string,
                        "tag": tag,
                    }


@pytest.fixture(params=get_test_data())
def image_data(request) -> Dict:
    """Provides ImageName instance and associated data."""
    return request.param


def test___init__(image_data: Dict):
    """Test that image name can be instantiated."""
    assert ImageName(
        digest=image_data["digest"],
        endpoint=image_data["endpoint"],
        image=image_data["image"],
        tag=image_data["tag"],
    )


def test___str__(image_data: Dict):
    """Test __str__ pass-through for different variants."""
    string = str(image_data["object"])
    assert image_data["image"] in string
    if image_data["digest"]:
        assert image_data["digest"] in string
    else:
        assert "sha256" not in string
    if "/" not in image_data["image"]:
        assert ImageName.DEFAULT_NAMESPACE not in string
    if image_data["endpoint"]:
        assert image_data["endpoint"] in string
    else:
        assert ImageName.DEFAULT_ENDPOINT not in string
    if image_data["tag"]:
        assert image_data["tag"] in string
    else:
        assert ImageName.DEFAULT_TAG not in string
    assert "None" not in string


def test_parse_string(image_data: Dict):
    """Test string parsing for complex image names."""
    result = ImageName._parse_string(image_data["string"])
    assert result["digest"] == image_data["digest"]
    if image_data["digest"]:
        assert isinstance(result["digest"], FormattedSHA256)
    assert result["endpoint"] == image_data["endpoint"]
    if image_data["endpoint"]:
        assert ImageName.DEFAULT_ENDPOINT not in str(result["endpoint"])
    assert result["image"] == image_data["image"]
    assert ImageName.DEFAULT_NAMESPACE not in str(result["image"])
    assert result["tag"] == image_data["tag"]
    if image_data["tag"]:
        assert ImageName.DEFAULT_TAG not in str(result["tag"])


def test_parse(image_data: Dict):
    """Test initialization via parsed strings."""
    image_name = ImageName.parse(image_data["string"])
    assert image_name.digest == image_data["digest"]
    if image_data["digest"]:
        assert isinstance(image_name.digest, FormattedSHA256)
    assert image_name.endpoint == image_data["endpoint"]
    if image_data["endpoint"]:
        assert ImageName.DEFAULT_ENDPOINT not in image_name.endpoint
    assert image_name.image == image_data["image"]
    assert ImageName.DEFAULT_NAMESPACE not in image_name.image
    assert image_name.tag == image_data["tag"]
    if image_data["tag"]:
        assert ImageName.DEFAULT_TAG not in image_name.tag


def test_digest(image_data: Dict):
    """Tests digest retrieval."""
    assert image_data["object"].digest == image_data["digest"]


def test_endpoint(image_data: Dict):
    """Tests endpoint retrieval."""
    assert image_data["object"].endpoint == image_data["endpoint"]


def test_image(image_data: Dict):
    """Tests image retrieval."""
    assert image_data["object"].image == image_data["image"]


def test_tag(image_data: Dict):
    """Tests tag retrieval."""
    assert image_data["object"].tag == image_data["tag"]


def test_resolve_digest(image_data: Dict):
    """Test digest resolution."""
    assert image_data["object"].resolve_digest() == image_data["digest"]


def test_resolve_endpoint(image_data: Dict):
    """Test endpoint resolution."""
    expected = (
        image_data["endpoint"] if image_data["endpoint"] else ImageName.DEFAULT_ENDPOINT
    )
    assert image_data["object"].resolve_endpoint() == expected


def test_resolve_image(image_data: Dict):
    """Test image resolution."""
    expected = (
        image_data["image"]
        if "/" in image_data["image"]
        else f"{ImageName.DEFAULT_NAMESPACE}/{image_data['image']}"
    )
    assert image_data["object"].resolve_image() == expected


def test_resolve_name(image_data: Dict):
    """Test name resolution."""
    assert image_data["object"].resolve_name() == str(image_data["object"])


def test_resolve_tag(image_data: Dict):
    """Test tag resolution."""
    expected = image_data["tag"] if image_data["tag"] else ImageName.DEFAULT_TAG
    assert image_data["object"].resolve_tag() == expected
