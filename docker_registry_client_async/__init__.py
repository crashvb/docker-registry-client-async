#!/usr/bin/env python

"""An AIOHTTP based Python REST client for the Docker Registry."""

from .dockerregistryclientasync import DockerRegistryClientAsync
from .formattedsha256 import FormattedSHA256
from .imagename import ImageName
from .jsonbytes import JsonBytes
from .manifest import Manifest
from .specs import (
    DockerAuthentication,
    DockerMediaTypes,
    Indices,
    MediaTypes,
    OCIMediaTypes,
    QuayAuthentication,
    RedHatAuthentication,
)

__all__ = (
    "DockerRegistryClientAsync",
    "FormattedSHA256",
    "ImageName",
    "JsonBytes",
    "Manifest",
    "DockerAuthentication",
    "DockerMediaTypes",
    "Indices",
    "MediaTypes",
    "OCIMediaTypes",
    "QuayAuthentication",
    "RedHatAuthentication",
)

__version__ = "1.0.3.dev0"
