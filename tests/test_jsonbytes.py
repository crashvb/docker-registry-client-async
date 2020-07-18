#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

from typing import Dict

import pytest

from docker_registry_client_async import (
    FormattedSHA256,
    JsonBytes,
)


@pytest.fixture()
def json_bytes_data() -> Dict:
    """Provides an JsonBytes instance."""
    _bytes = b'{"x":"1"}'
    return {"bytes": _bytes, "json_bytes": JsonBytes(_bytes)}


def test___init__(json_bytes_data: Dict):
    """Test that an json_bytes can be instantiated."""
    json_bytes = json_bytes_data["json_bytes"]
    assert json_bytes
    assert json_bytes.bytes == json_bytes_data["bytes"]
    assert json_bytes.json


def test___bytes__(json_bytes_data: Dict):
    """Test __str__ pass-through for different variants."""
    assert bytes(json_bytes_data["json_bytes"]) == json_bytes_data["bytes"]


def test___str__(json_bytes_data: Dict):
    """Test __str__ pass-through for different variants."""
    string = str(json_bytes_data["json_bytes"])
    assert string
    assert "None" not in string


def test_get_bytes(json_bytes_data: Dict):
    """Test raw image json_bytes retrieval."""
    assert json_bytes_data["json_bytes"].get_bytes() == json_bytes_data["bytes"]


def test_get_digest(json_bytes_data: Dict):
    """Test raw image json_bytes retrieval."""
    digest = json_bytes_data["json_bytes"].get_digest()
    assert digest == FormattedSHA256.calculate(json_bytes_data["bytes"])


def test_get_json(json_bytes_data: Dict):
    """Test image json_bytes retrieval."""
    assert json_bytes_data["json_bytes"].get_json()
