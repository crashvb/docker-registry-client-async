#!/usr/bin/env python

"""
JSON without canonicalization really bytes ;)
"""

import json

from copy import deepcopy

import canonicaljson

from .formattedsha256 import FormattedSHA256


class JsonBytes:
    """
    Abstract base class to canonicalize JSON and track the bytes representation.
    """

    def __init__(self, _bytes: bytes):
        """
        Args:
            _bytes: The raw bytes value.
        """
        self.bytes = self.json = None
        self._set_bytes(_bytes)

    def __bytes__(self):
        return self.get_bytes()

    def __str__(self):
        return self.get_bytes().decode("utf-8")

    def _set_bytes(self, _bytes: bytes):
        """
        Assigns the raw bytes and updates the internal JSON object.

        Args:
            _bytes: The raw bytes value.
        """
        self.bytes = _bytes
        self.json = json.loads(self.bytes)

    def _set_json(self, _json):
        """
        Assigns the internal JSON object and updates the raw bytes value.

        Args:
            _json: The internal JSON object.
        """
        self.json = _json
        self.bytes = canonicaljson.encode_canonical_json(self.json)

    def clone(self):
        """
        Initializes an returns a copy of this instance.

        Returns: A copy of this instance.
        """
        return deepcopy(self)

    def get_bytes(self) -> bytes:
        """
        Retrieves the raw image bytes.

        Returns:
            The raw image bytes.
        """
        return self.bytes

    def get_digest(self) -> FormattedSHA256:
        """
        Retrieves the SHA256 digest value of the raw bytes value.

        Returns:
            The SHA256 digest value of the raw image bytes.
        """
        return FormattedSHA256.calculate(self.get_bytes())

    def get_json(self):
        """
        Retrieves the image bytes in JSON form.

        Returns:
            The image bytes in JSON form.
        """
        return deepcopy(self.json)
