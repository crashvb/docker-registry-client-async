# docker-registry-client-async

[![pypi version](https://img.shields.io/pypi/v/docker-registry-client-async.svg)](https://pypi.org/project/docker-registry-client-async)
[![build status](https://github.com/crashvb/docker-registry-client-async/actions/workflows/main.yml/badge.svg)](https://github.com/crashvb/docker-registry-client-async/actions)
[![coverage status](https://coveralls.io/repos/github/crashvb/docker-registry-client-async/badge.svg)](https://coveralls.io/github/crashvb/docker-registry-client-async)
[![python versions](https://img.shields.io/pypi/pyversions/docker-registry-client-async.svg?logo=python&logoColor=FBE072)](https://pypi.org/project/docker-registry-client-async)
[![linting](https://img.shields.io/badge/linting-pylint-yellowgreen)](https://github.com/PyCQA/pylint)
[![code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![license](https://img.shields.io/github/license/crashvb/docker-registry-client-async.svg)](https://github.com/crashvb/docker-registry-client-async/blob/master/LICENSE.md)

## Overview

An AIOHTTP based Python REST client for the Docker Registry.

## Getting Started

```python
import asyncio
import json
from docker_registry_client_async import DockerRegistryClientAsync, FormattedSHA256, ImageName, Manifest

async def get_config(drca: DockerRegistryClientAsync, image_name: ImageName, manifest: Manifest) -> bytes:
    config_digest = FormattedSHA256.parse(manifest.get_json()["config"]["digest"])
    result = await drca.get_blob(image_name, config_digest)
    return json.loads(result["blob"].decode("utf-8"))

async def get_manifest(drca: DockerRegistryClientAsync, image_name: ImageName) -> Manifest:
    result = await drca.get_manifest(image_name)
    return result["manifest"]

async def main():
    image_name = ImageName.parse("busybox:1.30.1")
    async with DockerRegistryClientAsync() as drca:
        manifest = await get_manifest(drca, image_name)
        config = await get_config(drca, image_name, manifest)
        print(config)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

```

## Installation
### From [pypi.org](https://pypi.org/project/docker-registry-client-async/)

```
$ pip install docker_registry_client_async
```

### From source code

```bash
$ git clone https://github.com/crashvb/docker-registry-client-async
$ cd docker-registry-client-async
$ virtualenv env
$ source env/bin/activate
$ python -m pip install --editable .[dev]
```

### Environment Variables

| Variable | Default Value | Description |
| ---------| ------------- | ----------- |
| DRCA\_CACERTS | | The path to the certificate trust store.
| DRCA\_CHUNK\_SIZE | 2097152 | The chunk size to use then replicating content.
| DRCA\_CREDENTIALS\_STORE | ~/.docker/config.json | The credentials store from which to retrieve registry credentials.
| DRCA\_DEBUG | | Adds additional debug logging, mainly for troubleshooting and development.
| DRCA\_DEFAULT\_REGISTRY | index.docker.io | The default registry index to use when resolving image names.
| DRCA\_DEFAULT\_NAMESPACE | library | The default registry namespace to use when resolving image names.
| DRCA\_DEFAULT\_TAG | latest | The default image tag to use when resolving image names.
| DRCA\_PROTOCOL | https | The default transport protocol to when communicating with a registry.

## Development

[Source Control](https://github.com/crashvb/docker-registry-client-async)
