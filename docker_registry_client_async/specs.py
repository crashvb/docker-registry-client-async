#!/usr/bin/env python

# pylint: disable=too-few-public-methods

"""Reusable string literals."""

GENERIC_OAUTH2_URL_PATTERN = (
    "{0}?service={1}&scope={2}&client_id=docker-registry-client-async"
)


class DockerAuthentication:
    """
    https://docs.docker.com/registry/spec/auth/token/
    https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md
    https://github.com/docker/distribution/blob/master/docs/spec/auth/scope.md
    """

    DOCKERHUB_URL_PATTERN = GENERIC_OAUTH2_URL_PATTERN

    SCOPE_REGISTRY_CATALOG = "registry:catalog:*"
    SCOPE_REPOSITORY_PULL_PATTERN = "repository:{0}:pull"
    SCOPE_REPOSITORY_PUSH_PATTERN = "repository:{0}:push"
    SCOPE_REPOSITORY_ALL_PATTERN = "repository:{0}:pull,push"


class DockerMediaTypes:
    """https://github.com/docker/distribution/blob/master/docs/spec/manifest-v2-2.md#manifest-list"""

    CONTAINER_IMAGE_V1 = "application/vnd.docker.container.image.v1+json"
    DISTRIBUTION_MANIFEST_LIST_V2 = (
        "application/vnd.docker.distribution.manifest.list.v2+json"
    )
    DISTRIBUTION_MANIFEST_V1 = "application/vnd.docker.distribution.manifest.v1+json"
    DISTRIBUTION_MANIFEST_V1_SIGNED = (
        "application/vnd.docker.distribution.manifest.v1+prettyjws"
    )
    DISTRIBUTION_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
    IMAGE_ROOTFS_DIFF = "application/vnd.docker.image.rootfs.diff.tar.gzip"
    IMAGE_ROOTFS_FOREIGN_DIFF = (
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
    )
    PLUGIN_V1 = "application/vnd.docker.plugin.v1+json"


class Indices:
    """Common registry indices."""

    DOCKERHUB = "index.docker.io"
    QUAY = "quay.io"
    REDHAT = "registry.redhat.io"


class QuayAuthentication:
    """https://docs.quay.io/api/"""

    QUAY_URL_PATTERN = GENERIC_OAUTH2_URL_PATTERN
    SCOPE_REPOSITORY_PULL_PATTERN = "repo:{0}:read"
    SCOPE_REPOSITORY_PUSH_PATTERN = "repo:{0}:write"
    SCOPE_REPOSITORY_ALL_PATTERN = "repo:{0}:read,write"


class MediaTypes:
    """Generic mime types."""

    ANY_ANY = "*/*"
    APPLICATION_ANY = "application/*"
    APPLICATION_JSON = "application/json"
    APPLICATION_OCTET_STREAM = "application/octet-stream"
    APPLICATION_YAML = "application/yaml"


class OCIMediaTypes:
    """https://github.com/opencontainers/image-spec/blob/master/media-types.md"""

    DESCRIPTOR_V1 = "application/vnd.oci.descriptor.v1+json"
    IMAGE_CONFIG_V1 = "application/vnd.oci.image.config.v1+json"
    IMAGE_INDEX_V1 = "application/vnd.oci.image.index.v1+json"
    IMAGE_LAYER_V1 = "application/vnd.oci.image.layer.v1.tar"
    IMAGE_LAYER_GZIP_V1 = "application/vnd.oci.image.layer.v1.tar+gzip"
    IMAGE_LAYER_ZSTD_V1 = "application/vnd.oci.image.layer.v1.tar+zstd"
    IMAGE_LAYER_NONDISTRIBUTABLE_V1 = (
        "application/vnd.oci.image.layer.nondistributable.v1.tar"
    )
    IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_V1 = (
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
    )
    IMAGE_LAYER_NONDISTRIBUTABLE_ZSTD_V1 = (
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
    )
    IMAGE_MANIFEST_V1 = "application/vnd.oci.image.manifest.v1+json"
    LAYOUT_HEADER_V1 = "application/vnd.oci.layout.header.v1+json"


class RedHatAuthentication:
    """https://access.redhat.com/articles/3560571"""

    REDHAT_URL_PATTERN = GENERIC_OAUTH2_URL_PATTERN
    SCOPE_REPOSITORY_PULL_PATTERN = "repository:{0}:pull"
    SCOPE_REPOSITORY_PUSH_PATTERN = "repository:{0}:push"
    SCOPE_REPOSITORY_ALL_PATTERN = "repository:{0}:pull,push"
