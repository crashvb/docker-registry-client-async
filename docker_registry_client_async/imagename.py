#!/usr/bin/env python

"""Class that provides parsing and formatting of docker image names."""

import os

from copy import deepcopy
from typing import Optional

from .formattedsha256 import FormattedSHA256
from .specs import Indices
from .typing import ImageNamePareString


class ImageName:
    """
    Docker image name abstraction.
    """

    DEFAULT_ENDPOINT = os.environ.get("DRCA_DEFAULT_REGISTRY", Indices.DOCKERHUB)
    DEFAULT_NAMESPACE = os.environ.get("DRCA_DEFAULT_NAMESPACE", "library")
    DEFAULT_TAG = os.environ.get("DRCA_DEFAULT_TAG", "latest")

    def __init__(
        self,
        image: str,
        *,
        digest: Optional[FormattedSHA256] = None,
        endpoint: Optional[str] = None,
        tag: Optional[str] = None,
    ):
        """
        Args:
            image: Name of the image, optionally including a namespace.
        Keyword Args:
            digest: Optional digest value.
            endpoint: Optional endpoint address for fully qualified image names.
            tag: Optional tag name.
        """
        self.digest = digest
        self.endpoint = endpoint
        self.image = image
        self.tag = tag

    def __str__(self):
        """Does not resolve component parts."""
        result = self.image
        if self.tag:
            result = f"{result}:{self.tag}"
        # Note: A digest does not require a tag, but if a tag exists, the digest must come after it.
        if self.digest:
            result = f"{result}@{self.digest}"
        if self.endpoint:
            result = f"{self.endpoint}/{result}"

        return result

    def clone(self) -> "ImageName":
        """
        Initializes an returns a copy of this instance.

        Returns: A copy of this instance.
        """
        return deepcopy(self)

    @staticmethod
    def _parse_string(string: str) -> ImageNamePareString:
        """
        Parses the endpoint, image, and tag from a given string.

        Args:
            string: The string to be parsed.

        Returns:
            dict:
                digest: The digest value.
                endpoint: The registry endpoint; address with optional port.
                image: The name of the image; the image name and optional namespace.
                tag: The tag name.
        """
        result = {"digest": None, "endpoint": None, "image": None, "tag": None}

        segments = string.split("/")

        parts = segments[-1].split(":")
        result["image"] = parts[0]
        if len(parts) == 1:
            # image
            pass
        elif len(parts) == 2:
            # image@sha256:digest OR image:tag
            if "@" in parts[0]:
                pieces = parts[0].split("@")
                result["image"] = pieces[0]
                result["digest"] = FormattedSHA256(parts[1])
            else:
                result["tag"] = parts[1]
        elif len(parts) == 3:
            # image:tag@sha256:digest
            pieces = parts[1].split("@")
            result["tag"] = pieces[0]
            result["digest"] = FormattedSHA256(parts[2])
        else:
            raise ValueError(f"Unable to parse string: {string}")

        if len(segments) == 1:
            # image[:tag]
            pass
        else:
            # host[:port]/[ns0..n/]image[:tag] OR ns0/[ns1..n/]image[:tag]

            # Note: https://docs.docker.com/engine/reference/commandline/tag/
            #
            #       An image name is made up of slash-separated name components, optionally prefixed by a registry
            #       hostname. The hostname must comply with standard DNS rules, but may not contain underscores. If a
            #       hostname is present, it may optionally be followed by a port number in the format :8080. ... Name
            #       components may contain lowercase letter, digits and separators. A separator is defined as a period,
            #       one or two underscores, or one or more dashes. A name component may not start or end with a
            #       separator. A tag name ... may contain lowercase and uppercase letters, digits, underscores, periods
            #       and dashes. A tag name may not start with a period or a dash ... .

            # Assumption: That endpoint addresses will contain at least one '.' (period) character, and by convention
            #             image namespaces will not.
            if len(segments) > 2:
                result["image"] = f"{'/'.join(segments[1:-1])}/{result['image']}"

            if any(x in segments[0] for x in [":", "."]):
                result["endpoint"] = segments[0]
            else:
                result["image"] = f"{segments[0]}/{result['image']}"

        return result

    @staticmethod
    def parse(image_name: str) -> "ImageName":
        """
        Initializes an ImageName from a given image name string.

        Args:
            image_name: String containing the image name to be parsed.

        Returns:
            The newly initialized object.
        """
        parsed = ImageName._parse_string(image_name)
        return ImageName(
            digest=parsed["digest"],
            endpoint=parsed["endpoint"],
            image=parsed["image"],
            tag=parsed["tag"],
        )

    def resolve_digest(self) -> FormattedSHA256:
        """
        Resolves the digest value.

        Returns:
            The explicit digest value, or None.
        """
        return self.digest

    def resolve_endpoint(self) -> str:
        """
        Resolves the registry endpoint.

        Returns:
            The explicit registry endpoint.
        """
        return self.endpoint if self.endpoint else ImageName.DEFAULT_ENDPOINT

    def resolve_image(self) -> str:
        """
        Resolves the name of the image.

        Returns:
            The explicit name of the image, with namespace.
        """
        if "/" not in self.image:
            return f"{ImageName.DEFAULT_NAMESPACE}/{self.image}"

        return self.image

    def resolve_name(self):
        """Helper function for explict formatting."""
        return str(self)

    def resolve_tag(self) -> str:
        """
        Resolves the tag name.

        Returns:
            The explicit tag name.
        """
        return self.tag if self.tag else ImageName.DEFAULT_TAG
