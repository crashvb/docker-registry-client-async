#!/usr/bin/env python

"""Asynchronous library tests."""

import logging

from socket import AF_INET

import pytest

from aiodns import DNSResolver
from aiodns.error import DNSError
from aiohttp import AsyncResolver
from pycares import ares_host_result

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.mark.parametrize(
    "domain,name_unqualified",
    [("google.com", "calendar"), ("microsoft.com", "answers")],
)
async def test_aiodns_domain_search_list(
    domain: str, event_loop, name_unqualified: str
):
    """Test that the domain search list is functioning."""
    dns_resolver = DNSResolver(loop=event_loop)
    name_qualified = f"{name_unqualified}.{domain}"

    # Fully Qualified
    response = await dns_resolver.gethostbyname(
        name_qualified, AF_INET
    )  # type: ares_host_result
    LOGGER.debug("Qualified resolution: %s", response)
    assert response.name
    assert (response.name == name_qualified) or (name_qualified in response.aliases)
    assert response.addresses

    # Unqualified w/o domain search list
    with pytest.raises(DNSError) as exception:
        await dns_resolver.gethostbyname(name_unqualified, AF_INET)
    assert "Domain name not found" in str(exception.value)

    dns_resolver = DNSResolver(domains=[domain], loop=event_loop)

    # Unqualified w/ domain search list
    response = await dns_resolver.gethostbyname(
        name_unqualified, AF_INET
    )  # type: ares_host_result
    LOGGER.debug("Unqualified resolution: %s", response)
    assert response.name
    assert (response.name == name_qualified) or next(
        alias for alias in response.aliases if alias.startswith(f"{name_unqualified}.")
    )
    assert response.addresses


@pytest.mark.parametrize(
    "domain,name_unqualified",
    [("google.com", "calendar"), ("microsoft.com", "answers")],
)
async def test_aiohttp_domain_search_list(
    domain: str, event_loop, name_unqualified: str
):
    """Test that the domain search list is functioning."""
    async_resolver = AsyncResolver(loop=event_loop)
    name_qualified = f"{name_unqualified}.{domain}"

    # Fully Qualified
    response = await async_resolver.resolve(name_qualified, family=AF_INET)
    LOGGER.debug("Qualified resolution: %s", response)
    assert response
    assert response[0]["hostname"] == name_qualified
    assert response[0]["host"]

    # Unqualified w/o domain search list
    with pytest.raises(OSError) as exception:
        await async_resolver.resolve(name_unqualified, family=AF_INET)
    assert "Domain name not found" in str(exception.value)

    async_resolver = AsyncResolver(domains=[domain], loop=event_loop)

    # Unqualified w/ domain search list
    response = await async_resolver.resolve(name_unqualified, family=AF_INET)
    LOGGER.debug("Unqualified resolution: %s", response)
    assert response
    assert response[0]["hostname"] == name_unqualified
    assert response[0]["host"]
