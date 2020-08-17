#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

from typing import TypedDict

import pytest

from docker_registry_client_async import (
    FormattedSHA256,
    JsonBytes,
)


class TypingJsonBytesData(TypedDict):
    # pylint: disable=missing-class-docstring
    bytes: bytes
    json_bytes: JsonBytes


@pytest.fixture()
def json_bytes_data() -> TypingJsonBytesData:
    """Provides an JsonBytes instance."""
    _bytes = b'{"x":"1"}'
    return {"bytes": _bytes, "json_bytes": JsonBytes(_bytes)}


def test___init__(json_bytes_data: TypingJsonBytesData):
    """Test that an json_bytes can be instantiated."""
    json_bytes = json_bytes_data["json_bytes"]
    assert json_bytes
    assert json_bytes.bytes == json_bytes_data["bytes"]
    assert json_bytes.json


def test___bytes__(json_bytes_data: TypingJsonBytesData):
    """Test __bytes__ pass-through for different variants."""
    assert bytes(json_bytes_data["json_bytes"]) == json_bytes_data["bytes"]


def test___str__(json_bytes_data: TypingJsonBytesData):
    """Test __str__ pass-through for different variants."""
    string = str(json_bytes_data["json_bytes"])
    assert string
    assert "None" not in string


def test_clone(json_bytes_data: TypingJsonBytesData):
    """Test object cloning."""
    clone = json_bytes_data["json_bytes"].clone()
    assert clone != json_bytes_data["json_bytes"]
    assert bytes(clone) == json_bytes_data["bytes"]
    assert str(clone) == str(json_bytes_data["json_bytes"])
    clone._set_json({})  # pylint: disable=protected-access
    assert bytes(clone) != json_bytes_data["json_bytes"]
    assert str(clone) != str(json_bytes_data["json_bytes"])


def test_get_bytes(json_bytes_data: TypingJsonBytesData):
    """Test raw image json_bytes retrieval."""
    assert json_bytes_data["json_bytes"].get_bytes() == json_bytes_data["bytes"]


def test_get_digest(json_bytes_data: TypingJsonBytesData):
    """Test raw image json_bytes retrieval."""
    digest = json_bytes_data["json_bytes"].get_digest()
    assert digest == FormattedSHA256.calculate(json_bytes_data["bytes"])


def test_get_json(json_bytes_data: TypingJsonBytesData):
    """Test image json_bytes retrieval."""
    assert json_bytes_data["json_bytes"].get_json()
