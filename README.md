# docker-registry-client-async

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

## Compatibility

* Tested with python 3.8

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
| DRCA_CACERTS | | The path to the certificate trust store.
| DRCA_CHUNK_SIZE | 2097152 | The chunk size to use then replicating content.
| DRCA_CREDENTIALS_STORE | ~/.docker/config.json | The credentials store from which to retrieve registry credentials.
| DRCA_DEFAULT_REGISTRY | index.docker.io | The default registry index to use when resolving image names.
| DRCA_DEFAULT_NAMESPACE | library | The default registry namespace to use when resolving image names.
| DRCA_DEFAULT_TAG | latest | The default image tag to use when resolving image names.
| DRCA_PROTOCOL | https | The default transport protocol to when communicating with a registry.
| DRCA_TOKEN_BASED_ENDPOINTS | index.docker.io,quay.io,registry.redhat.io | Endpoints for which to retrieve authentication tokens.

## Development

[Source Control](https://github.com/crashvb/docker-registry-client-async)
