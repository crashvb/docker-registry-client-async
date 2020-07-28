#!/usr/bin/env python

"""Utility classes."""

import hashlib


class FormattedSHA256(str):
    """A algorithm prefixed SHA256 hash value."""

    def __new__(cls, sha256: str):
        if sha256:
            sha256 = sha256.replace("sha256:", "")
        if not sha256 or len(sha256) != 64:
            raise ValueError(sha256)
        obj = super().__new__(cls, f"sha256:{sha256}")
        obj.sha256 = sha256
        return obj

    @staticmethod
    def parse(digest: str) -> "FormattedSHA256":
        """
        Initializes a FormattedSHA256 from a given SHA256 digest value.

        Args:
            digest: A SHA256 digest value in form SHA256:<digest value>.

        Returns:
            The newly initialized object.
        """
        if not digest or not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError(digest)
        return FormattedSHA256(digest[7:])

    @staticmethod
    def calculate(data: bytes) -> "FormattedSHA256":
        """
        Calculates the digest value for given data.

        Args:
            data: The data for which to calculate the digest value.

        Returns:
            The FormattedSHA256 containing the corresponding digest value.
        """
        return FormattedSHA256(hashlib.sha256(data).hexdigest())
