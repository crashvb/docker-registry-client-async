#!/usr/bin/env python

"""Utility classes."""

import hashlib
import os

from functools import wraps, partial

import asyncio

from aiohttp import ClientResponse

from .formattedsha256 import FormattedSHA256
from .typing import UtilsChunkToFile

# https://github.com/docker/docker-py/blob/master/docker/constants.py
CHUNK_SIZE = int(os.environ.get("DRCA_CHUNK_SIZE", 2097152))


def async_wrap(func):
    """Decorates a given function for execution via an executor."""
    # https://dev.to/0xbf/turn-sync-function-to-async-python-tips-58nn
    @wraps(func)
    async def run_in_executor(*args, loop=None, executor=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        partial_func = partial(func, *args, **kwargs)
        return await loop.run_in_executor(executor, partial_func)

    return run_in_executor


async def be_kind_rewind(file, *, file_is_async: bool = True):
    """
    Reset the file position (offset) to the absolute beginning.
    Args:
        file: The file for which to reset the offset.
        file_is_async: If True, all file IO operations will be awaited.
    """
    if file_is_async:
        coroutine = file.seek(0)
    else:
        coroutine = async_wrap(file.seek)(0)
    await coroutine


async def chunk_to_file(
    client_response: ClientResponse, file, *, file_is_async: bool = True
) -> UtilsChunkToFile:
    """
    Asynchronously stores file chunks to a given file.

    Args:
        client_response: The client response from which to read the file chunks.
        file: The file to which to store the file chunks.
        file_is_async: If True, all file IO operations will be awaited.

    Returns:
        dict:
            client_response: The underlying client response.
            digest: The digest value of the chunked data.
            size: The byte size of the chunked data in bytes.
    """
    # https://docs.aiohttp.org/en/stable/streams.html
    hasher = hashlib.sha256()
    size = 0
    # TODO: Do we need to use a max chunk size here (i.e. switch from iter_chunks() to iter_chunked)?
    coroutine = file.write if file_is_async else async_wrap(file.write)
    async for chunk, _ in client_response.content.iter_chunks():
        await coroutine(chunk)
        hasher.update(chunk)
        size += len(chunk)

    await be_kind_rewind(file, file_is_async=file_is_async)

    return UtilsChunkToFile(
        client_response=client_response,
        digest=FormattedSHA256(hasher.hexdigest()),
        size=size,
    )


def must_be_equal(
    expected,
    actual,
    msg: str = "Actual value does not match expected value",
    *,
    error_type=RuntimeError,
):
    """
    Compares two values and raises an exception if they are not equal.

    Args:
        expected: The expected value.
        actual: The actual value.
        msg: Message describing the context of the comparison.
        error_type: The type of exception to be raised if not equal.
    """
    if actual != expected:
        raise error_type(f"{msg}: {actual} != {expected}")
