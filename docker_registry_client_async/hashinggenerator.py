#!/usr/bin/env python

"""Generators tht hash the data they retrieve."""

import hashlib

from .formattedsha256 import FormattedSHA256
from .utils import async_wrap, be_kind_rewind, CHUNK_SIZE


class HashingGenerator:
    """
    Generator that hashes the data it retrieves.
    """

    def __init__(self, file, *, file_is_async: bool = True):
        """
        Args:
            file: The file to which to retrieve the file chunks.
            file_is_async: If True, all file IO operations will be awaited.
        """
        self.file = file
        self.file_is_async = file_is_async
        self.hasher = hashlib.sha256()
        self.size = 0

    async def __aiter__(self):
        # https://docs.aiohttp.org/en/stable/client_quickstart.html#streaming-uploads
        coroutine = self.file.read if self.file_is_async else async_wrap(self.file.read)
        while True:
            chunk = await coroutine(CHUNK_SIZE)
            if not chunk:
                break
            self.hasher.update(chunk)
            self.size += len(chunk)
            yield chunk

        await be_kind_rewind(self.file, file_is_async=self.file_is_async)

    def get_digest(self) -> FormattedSHA256:
        """Retrieves the digest value of the read data."""
        return FormattedSHA256(self.hasher.hexdigest())

    def get_size(self) -> int:
        """Retrieves the size (length) of the read data."""
        return self.size
