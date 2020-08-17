#!/usr/bin/env python

"""
Abstraction of a docker image configuration, as defined in:

* https://github.com/docker/distribution/tree/master/docs/spec
* https://github.com/opencontainers/image-spec/blob/master/media-types.md
"""

from .jsonbytes import JsonBytes
from .specs import DockerMediaTypes, MediaTypes, OCIMediaTypes


class Manifest(JsonBytes):
    """
    Abstract class to retrieve and manipulate image manifests.
    """

    def __init__(self, manifest: bytes, *, media_type: str = None):
        """
        Args:
            manifest: The raw image manifest value.
            media_type: The media type of the image manifest.
        """
        self.media_type = None
        self._set_media_type(media_type)
        super().__init__(manifest)

    def _detect_media_type(self):
        """
        Attempts to detect the media type of the image manifest.
        """
        # Is there a declared media type (applies to all of Docker manifest v2.2)?
        if "mediaType" in self.get_json():
            self._set_media_type(self.get_json()["mediaType"])

        # Is this an OCI image index?
        elif "manifests" in self.get_json():
            self._set_media_type(OCIMediaTypes.IMAGE_INDEX_V1)

        # Is this an OCI image manifest?
        elif "layers" in self.get_json():
            self._set_media_type(OCIMediaTypes.IMAGE_MANIFEST_V1)

        # Is this a Docker manifest v2.1?
        elif "fsLayers" in self.get_json():
            self._set_media_type(DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED)

        # Give up
        else:
            self._set_media_type(MediaTypes.APPLICATION_JSON)

    def _set_bytes(self, _bytes: bytes):
        """
        Assigns the raw bytes and updates the internal JSON object.

        Args:
            _bytes: The raw bytes value.
        """
        super()._set_bytes(_bytes)
        if not self.media_type:
            self._detect_media_type()

    def _set_json(self, json):
        """
        Assigns the internal JSON object and updates the raw bytes value.

        Args:
            json: The internal JSON object.
        """
        super()._set_json(json)
        if not self.media_type:
            self._detect_media_type()

    def _set_media_type(self, media_type: str):
        """
        Assigns the media type of the image manifest.

        Args:
            media_type: The media type of the image manifest.
        """
        self.media_type = media_type

    def get_media_type(self) -> str:
        """
        Retrieves the media type of the image manifest.

        Returns:
            The media type of the image manifest.
        """
        return self.media_type
