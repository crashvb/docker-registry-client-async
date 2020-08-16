#!/usr/bin/env python

"""Formatted SHA256 tests."""

import pytest

from docker_registry_client_async import FormattedSHA256


def test___new__():
    """Test that a formatted SHA256 can be instantiated."""
    digest = "0123456789012345678901234567890123456789012345678901234567890123"
    formattedsha256 = FormattedSHA256(digest)
    assert formattedsha256
    assert formattedsha256.sha256 == digest  # pylint: disable=no-member
    assert str(formattedsha256) == f"sha256:{digest}"

    digest = "sha256:0123456789012345678901234567890123456789012345678901234567890123"
    formattedsha256 = FormattedSHA256(digest)
    assert formattedsha256
    assert formattedsha256.sha256 == digest[7:]  # pylint: disable=no-member
    assert str(formattedsha256) == digest

    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256(None)
    assert "None" in str(exc_info.value)

    digest = "012345678901234567890123456789012345678901234567890123456789012"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256(digest)
    assert digest in str(exc_info.value)

    digest = "sha1:0123456789012345678901234567890123456789012345678901234567890123"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256(digest)
    assert digest in str(exc_info.value)


def test_parse():
    """Test that a formatted SHA256 can be parsed."""
    digest = "0123456789012345678901234567890123456789012345678901234567890123"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256.parse(digest)
    assert digest in str(exc_info.value)

    digest = "sha256:0123456789012345678901234567890123456789012345678901234567890123"
    formattedsha256 = FormattedSHA256.parse(digest)
    assert formattedsha256
    assert formattedsha256.sha256 == digest[7:]  # pylint: disable=no-member
    assert str(formattedsha256) == digest

    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256.parse(None)
    assert "None" in str(exc_info.value)

    digest = "012345678901234567890123456789012345678901234567890123456789012"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256.parse(digest)
    assert digest in str(exc_info.value)

    digest = "sha256:012345678901234567890123456789012345678901234567890123456789012"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256.parse(digest)
    assert digest in str(exc_info.value)

    digest = "sha1:0123456789012345678901234567890123456789012345678901234567890123"
    with pytest.raises(ValueError) as exc_info:
        FormattedSHA256.parse(digest)
    assert digest in str(exc_info.value)


def test_calculate():
    """Test that a formatted SHA256 can be calculated."""
    assert (
        FormattedSHA256.calculate(b"test data")
        == "sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    )
