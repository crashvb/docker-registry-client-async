# docker-registry-client-async

## Overview

An AIOHTTP based Python REST client for the Docker Registry.

## Compatibility

* Tested with python 3.8

## Installation
### From [pypi.org](https://pypi.org/project/docker_registry_client_async/)

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
| DRCA_CHUNK_SIZE | 2097152 | The chunk size to use then replicating content.
| DRCA_CREDENTIALS_STORE | ~/.docker/config.json | The credentials store from which to retrieve registry credentials.
| DRCA_DEFAULT_REGISTRY | index.docker.io | The default registry index to use when resolving image names.
| DRCA_DEFAULT_NAMESPACE | library | The default registry namespace to use when resolving image names.
| DRCA_DEFAULT_TAG | latest | The default image tag to use when resolving image names.
| DRCA_PROTOCOL | https | The default transport protocol to when communicating with a registry.
| DRCA_TOKEN_BASED_ENDPOINTS | index.docker.io,quay.io,registry.redhat.io | Endpoints for which to retrieve authentication tokens.

## Development

[Source Control](https://github.com/crashvb/docker-registry-client-async)
