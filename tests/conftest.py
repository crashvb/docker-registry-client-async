#!/usr/bin/env python

"""Configures execution of pytest."""

import pytest


def pytest_addoption(parser):
    """pytest add option."""
    parser.addoption(
        "--allow-online",
        action="store_true",
        default=False,
        help="Allow execution of online tests.",
    )
    parser.addoption(
        "--allow-online-deletion",
        action="store_true",
        default=False,
        help="Allow deletion of online content (implies --allow-online-modification).",
    )
    parser.addoption(
        "--allow-online-modification",
        action="store_true",
        default=False,
        help="Allow modification of online content (implies --allow-online).",
    )


def pytest_collection_modifyitems(config, items):
    """pytest collection modifier."""

    skip_online = pytest.mark.skip(
        reason="Execution of online tests requires --allow-online option."
    )
    skip_online_deletion = pytest.mark.skip(
        reason="Deletion of online content requires --allow-online-deletion option."
    )
    skip_online_modification = pytest.mark.skip(
        reason="Modification of online content requires --allow-online-modification option."
    )
    for item in items:
        if "online_deletion" in item.keywords and not config.getoption(
            "--allow-online-deletion"
        ):
            item.add_marker(skip_online_deletion)
        elif (
            "online_modification" in item.keywords
            and not config.getoption("--allow-online-deletion")
            and not config.getoption("--allow-online-modification")
        ):
            item.add_marker(skip_online_modification)
        elif (
            "online" in item.keywords
            and not config.getoption("--allow-online")
            and not config.getoption("--allow-online-deletion")
            and not config.getoption("--allow-online-modification")
        ):
            item.add_marker(skip_online)


def pytest_configure(config):
    """pytest configuration hook."""
    config.addinivalue_line("markers", "online: allow execution of online tests.")
    config.addinivalue_line(
        "markers", "online_deletion: allow deletion of online content."
    )
    config.addinivalue_line(
        "markers", "online_modification: allow modification of online content."
    )
