#!/usr/bin/env python

# pylint: disable=redefined-outer-name,protected-access

"""ImageName tests."""

from time import time
from typing import Generator, NamedTuple

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName


class TypingGetTestData(NamedTuple):
    # pylint: disable=missing-class-docstring
    digest: FormattedSHA256
    endpoint: str
    image: str
    object: ImageName
    string: str
    tag: str


def get_test_data() -> Generator[TypingGetTestData, None, None]:
    # pylint: disable=too-many-nested-blocks
    """Dynamically initializes test data."""
    for endpoint in ["endpoint.io", "endpoint:port", "endpoint.io:port", None]:
        for slash in ["", "/"]:
            for _image in ["image", "ns0/image", "ns0/ns1/image", "ns0/ns1/ns2/image"]:
                image = f"{slash}{_image}"
                for tag in ["tag", None]:
                    for digest in [FormattedSHA256.calculate(b""), None]:
                        # Construct a complex string ...
                        string = image
                        if tag:
                            string = f"{string}:{tag}"
                        if digest:
                            string = f"{string}@{digest}"
                        if endpoint:
                            if string.startswith("/"):
                                string = string[1:]
                            string = f"{endpoint}/{string}"
                        yield TypingGetTestData(
                            digest=digest,
                            endpoint=endpoint,  # Should be normalized to not have a trailing slash
                            image=_image,  # Should be normalized to not have a leading slash
                            object=ImageName.parse(string),
                            string=string,
                            tag=tag,
                        )


@pytest.fixture(params=get_test_data())
def image_data(request) -> TypingGetTestData:
    """Provides ImageName instance and associated data."""
    return request.param


def test___init__(image_data: TypingGetTestData):
    """Test that image name can be instantiated."""
    assert ImageName(
        digest=image_data.digest,
        endpoint=image_data.endpoint,
        image=image_data.image,
        tag=image_data.tag,
    )


def test___eq__():
    # pylint: disable=comparison-with-itself
    """Test __eq__ pass-through for different variants."""
    image_name0 = ImageName.parse("a")
    image_name1 = ImageName.parse("a")
    assert image_name0 == image_name0
    assert image_name0 == image_name1
    assert image_name1 == image_name0
    assert image_name1 == image_name1

    image_name2 = ImageName.parse("b")
    assert image_name0 != image_name2
    assert image_name2 != image_name0


def test___lt__():
    """Test __lt__ pass-through for different variants."""
    image_name0 = ImageName.parse("a")
    image_name1 = ImageName.parse("b")
    assert image_name0 < image_name1
    assert image_name1 > image_name0


def test___hash():
    """Test __str__ pass-through for different variants."""
    hash0 = hash(ImageName.parse("a"))
    hash1 = hash(ImageName.parse("a"))
    hash2 = hash(ImageName.parse("b"))
    assert hash0 == hash1
    assert hash0 != hash2


def test___str__(image_data: TypingGetTestData):
    """Test __str__ pass-through for different variants."""
    string = str(image_data.object)
    assert image_data.image in string
    assert not string.startswith("/")
    if image_data.digest:
        assert image_data.digest in string
    else:
        assert "sha256" not in string
    if "/" not in image_data.image:
        assert ImageName.DEFAULT_NAMESPACE not in string
    if image_data.endpoint:
        assert image_data.endpoint in string
    else:
        assert ImageName.DEFAULT_ENDPOINT not in string
    if image_data.tag:
        assert image_data.tag in string
    else:
        assert ImageName.DEFAULT_TAG not in string
    assert "None" not in string


def test_clone(image_data: TypingGetTestData):
    """Test object cloning."""
    clone = image_data.object.clone()
    assert id(clone) != id(image_data.object)
    assert clone == image_data.object
    assert str(clone) == str(image_data.object)
    clone.endpoint = "gemini.man"
    assert clone != image_data.object
    assert str(clone) != str(image_data.object)


def test_parse_string(image_data: TypingGetTestData):
    """Test string parsing for complex image names."""
    result = ImageName._parse_string(image_data.string)
    assert result.digest == image_data.digest
    if image_data.digest:
        assert isinstance(result.digest, FormattedSHA256)
    assert result.endpoint == image_data.endpoint
    if image_data.endpoint:
        assert ImageName.DEFAULT_ENDPOINT not in str(result.endpoint)
        assert not result.endpoint.endswith("/")
    assert result.image == image_data.image
    assert not result.image.startswith("/")
    assert ImageName.DEFAULT_NAMESPACE not in str(result.image)
    assert result.tag == image_data.tag
    if image_data.tag:
        assert ImageName.DEFAULT_TAG not in str(result.tag)


def test_parse(image_data: TypingGetTestData):
    """Test initialization via parsed strings."""
    image_name = ImageName.parse(image_data.string)
    assert image_name.digest == image_data.digest
    if image_data.digest:
        assert isinstance(image_name.digest, FormattedSHA256)
    assert image_name.endpoint == image_data.endpoint
    if image_data.endpoint:
        assert ImageName.DEFAULT_ENDPOINT not in image_name.endpoint
    assert image_name.image == image_data.image
    assert ImageName.DEFAULT_NAMESPACE not in image_name.image
    assert image_name.tag == image_data.tag
    if image_data.tag:
        assert ImageName.DEFAULT_TAG not in image_name.tag

    with pytest.raises(ValueError) as exception:
        ImageName.parse("a:b:c:d")
    assert str(exception.value).startswith("Unable to parse string:")


def test_digest(image_data: TypingGetTestData):
    """Tests digest retrieval."""
    assert image_data.object.digest == image_data.digest


def test_endpoint(image_data: TypingGetTestData):
    """Tests endpoint retrieval."""
    assert image_data.object.endpoint == image_data.endpoint


def test_image(image_data: TypingGetTestData):
    """Tests image retrieval."""
    assert image_data.object.image == image_data.image


def test_tag(image_data: TypingGetTestData):
    """Tests tag retrieval."""
    assert image_data.object.tag == image_data.tag


def test_resolve_digest(image_data: TypingGetTestData):
    """Test digest resolution."""
    assert image_data.object.resolve_digest() == image_data.digest


def test_resolve_endpoint(image_data: TypingGetTestData):
    """Test endpoint resolution."""
    expected = (
        image_data.endpoint if image_data.endpoint else ImageName.DEFAULT_ENDPOINT
    )
    assert image_data.object.resolve_endpoint() == expected


def test_resolve_image(image_data: TypingGetTestData):
    """Test image resolution."""
    expected = (
        image_data.image
        if "/" in image_data.image
        else f"{ImageName.DEFAULT_NAMESPACE}/{image_data.image}"
    )
    assert image_data.object.resolve_image() == expected


def test_resolve_name(image_data: TypingGetTestData):
    """Test name resolution."""
    assert image_data.object.resolve_name() == str(image_data.object)


def test_resolve_tag(image_data: TypingGetTestData):
    """Test tag resolution."""
    expected = image_data.tag if image_data.tag else ImageName.DEFAULT_TAG
    assert image_data.object.resolve_tag() == expected


def test_set_digest(image_data: TypingGetTestData):
    """Tests digest assignment."""
    assert image_data.object.digest == image_data.digest
    value = FormattedSHA256.calculate(f"data:{time()}".encode(encoding="utf-8"))
    assert image_data.object.set_digest(value) == image_data.object
    assert image_data.object.digest == value


def test_set_endpoint(image_data: TypingGetTestData):
    """Tests endpoint assignment."""
    assert image_data.object.endpoint == image_data.endpoint
    value = f"data:{time()}"
    assert image_data.object.set_endpoint(value) == image_data.object
    assert image_data.object.endpoint == value


def test_set_image(image_data: TypingGetTestData):
    """Tests image assignment."""
    assert image_data.object.image == image_data.image
    value = f"data/{time()}"
    assert image_data.object.set_image(value) == image_data.object
    assert image_data.object.image == value


def test_set_tag(image_data: TypingGetTestData):
    """Tests tag assignment."""
    assert image_data.object.tag == image_data.tag
    value = f"data:{time()}"
    assert image_data.object.set_tag(value) == image_data.object
    assert image_data.object.tag == value
