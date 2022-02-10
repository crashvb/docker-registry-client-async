#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Utilities tests."""

from pathlib import Path
from typing import Any

import aiofiles
import pytest

from aiohttp import AsyncResolver, ClientSession, TCPConnector

from docker_registry_client_async import FormattedSHA256
from docker_registry_client_async.utils import (
    async_wrap,
    be_kind_rewind,
    chunk_to_file,
    must_be_equal,
)

from .testutils import hash_file

pytestmark = [pytest.mark.asyncio]


@pytest.fixture
async def client_session() -> ClientSession:
    """Provides a ClientSession instance."""
    # Do not use caching; get a new instance for each test
    async with ClientSession(
        connector=TCPConnector(resolver=AsyncResolver())
    ) as client_session:
        yield client_session


async def test_async_wrap():
    """Tests that a synchronous function can be executed in an asynchronous event loop."""

    keyword_default = "default_keyword_value"
    function_result_pattern = (
        "function result argument=[{0}] args=[{1}] keyword=[{2}] kwargs=[{3}]"
    )

    @async_wrap
    def sync_func1(argument, *args, keyword=keyword_default, **kwargs):
        return function_result_pattern.format(argument, args, keyword, kwargs)

    def sync_func2(argument, *args, keyword=keyword_default, **kwargs):
        return function_result_pattern.format(argument, args, keyword, kwargs)

    argument_expected = "expected_argument_value"
    keyword_expected = "expected_keyword_value"
    args_expected = ("argument1", "argument2")
    kwargs_expected = {"keyword1": "value1", "keyword2": "value2"}
    result = await sync_func1(
        argument_expected, *args_expected, keyword=keyword_expected, **kwargs_expected
    )
    assert all(
        x in result
        for x in [
            argument_expected,
            str(args_expected),
            keyword_expected,
            str(kwargs_expected),
        ]
    )

    coroutine = async_wrap(sync_func2)
    result = await coroutine(
        argument_expected, *args_expected, keyword=keyword_expected, **kwargs_expected
    )
    assert all(
        x in result
        for x in [
            argument_expected,
            str(args_expected),
            keyword_expected,
            str(kwargs_expected),
        ]
    )


async def test_be_kind_rewind(tmp_path: Path):
    """Tests that the position within a file can be assigned"""
    content = "This is test content."
    path_async = tmp_path.joinpath("test_async")
    async with aiofiles.open(path_async, mode="w") as file:
        await file.write(content)
        assert await file.tell() > 0
        await be_kind_rewind(file)
        assert await file.tell() == 0

    path_sync = tmp_path.joinpath("test_sync")
    with path_sync.open("w") as file:
        file.write(content)
        assert file.tell() > 0
        await be_kind_rewind(file, file_is_async=False)
        assert file.tell() == 0


@pytest.mark.online
async def test_chunk_file(client_session: ClientSession, tmp_path: Path):
    """Tests that remote files can be chunked to disk."""
    url = "https://tools.ietf.org/rfc/rfc2616.txt"  # Hat tip
    digest_expected = FormattedSHA256.parse(
        "sha256:10211d2885196b97b1c78e1672f3f68ae97c294596ef2b7fd890cbd30a3427bf"
    )
    size = 422279

    async with client_session.get(url=url, allow_redirects=True) as client_response:
        path_async = tmp_path.joinpath("test_async")
        async with aiofiles.open(path_async, mode="w+b") as file:
            result = await chunk_to_file(client_response, file)
        assert result.client_response == client_response
        assert result.digest == digest_expected
        assert result.size == size

        digest_actual = await hash_file(path_async)
        assert digest_actual == digest_expected

    path_sync = tmp_path.joinpath("test_sync")
    async with client_session.get(url=url, allow_redirects=True) as client_response:
        with path_sync.open("w+b") as file:
            result = await chunk_to_file(client_response, file, file_is_async=False)
        assert result.client_response == client_response
        assert result.digest == digest_expected
        assert result.size == size

        digest_actual = await hash_file(path_async)
        assert digest_actual == digest_expected


@pytest.mark.parametrize(
    "expected,actual,result",
    [
        ("1", "1", True),
        ("1", "0", False),
        ("1", 1, False),
        (1, 1, True),
        (1, 0, False),
        ("1", None, False),
        (1, None, False),
        (None, None, True),
    ],
)
async def test_must_be_equal(expected: Any, actual: Any, result: bool):
    """Test that equality can be determined."""
    if not result:
        with pytest.raises(RuntimeError) as exc_info:
            must_be_equal(expected, actual)
        assert str(expected) in str(exc_info.value)
        assert str(actual) in str(exc_info.value)
        assert "does not match" in str(exc_info.value)
    else:
        must_be_equal(expected, actual)


async def test_must_be_equal_msg(expected: Any = "bar", actual: Any = "foo"):
    """Test that an custom error message can be used."""
    message = "custom message here"
    with pytest.raises(RuntimeError) as exc_info:
        must_be_equal(expected, actual, message)
    assert str(expected) in str(exc_info.value)
    assert str(actual) in str(exc_info.value)
    assert message in str(exc_info.value)
