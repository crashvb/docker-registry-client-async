#!/usr/bin/env python

"""Utility classes."""

import hashlib
import os

from typing import Dict

from aiohttp import ClientResponse

from .formattedsha256 import FormattedSHA256

# https://github.com/docker/docker-py/blob/master/docker/constants.py
CHUNK_SIZE = int(os.environ.get("DRCA_CHUNK_SIZE", 2097152))


async def chunk_from_disk(file, file_is_async: bool = True) -> bytes:
    """
    Retrieves files chunks from disk.

    Args:
        file: The file to which to retrieve the file chunks.
        file_is_async: If True, all file IO operations will be awaited.

    Yields:
        The next file chunk.
    """
    # https://docs.aiohttp.org/en/stable/client_quickstart.html#streaming-uploads
    while True:
        if file_is_async:
            chunk = await file.read(CHUNK_SIZE)
        else:
            chunk = file.read(CHUNK_SIZE)
        if not chunk:
            break
        yield chunk

    # Be kind, rewind ...
    if file_is_async:
        await file.seek(0)
    else:
        file.seek(0)


async def chunk_to_disk(
    client_response: ClientResponse, file, file_is_async: bool = True
) -> Dict:
    """
    Stores files chunks to disk.

    Args:
        client_response: The client response from which to read the file chunks.
        file: The file to which to store the file chunks.
        file_is_async: If True, all file IO operations will be awaited.

    Returns:
        dict:
            client_response: The underlying client response.
            digest: The digest value of the chunked data.
            size: The byte size of the chunked data.
    """
    # https://docs.aiohttp.org/en/stable/streams.html
    hasher = hashlib.sha256()
    size = 0
    # TODO: Do we need to use a max chunk size here (i.e. switch from iter_chunks() to iter_chunked)?
    async for chunk, _ in client_response.content.iter_chunks():
        if file_is_async:
            await file.write(chunk)
        else:
            # TODO: https://dev.to/0xbf/turn-sync-function-to-async-python-tips-58nn
            file.write(chunk)
        hasher.update(chunk)
        size += len(chunk)

    # Be kind, rewind ...
    if file_is_async:
        await file.seek(0)
    else:
        file.seek(0)

    return {
        "client_response": client_response,
        "digest": FormattedSHA256(hasher.hexdigest()),
        "size": size,
    }


def must_be_equal(
    expected, actual, msg: str = "Actual value does not match expected value"
):
    """
    Compares two values and raises an exception if they are not equal.

    Args:
        expected: The expected value.
        actual: The actual value.
        msg: Message describing the context of the comparison.
    """
    if actual != expected:
        raise RuntimeError("{0}: {1} != {2}".format(msg, actual, expected))
