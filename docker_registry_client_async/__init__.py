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
)

__version__ = "0.1.8"
