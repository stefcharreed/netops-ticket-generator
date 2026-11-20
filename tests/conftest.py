"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def _builtin_icons_only(tmp_path_factory, monkeypatch):
    """Every test draws with the built-in icons: Cisco's icon files never touch the test suite."""
    monkeypatch.setenv("PACKETGEN_ICONS", str(tmp_path_factory.mktemp("no-icons")))
