"""Pytest config for async tests."""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as an async test"
    )


@pytest.fixture
def anyio_backend():
    return "asyncio"
