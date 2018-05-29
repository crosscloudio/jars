"""Fixtures for testing microsoft_graph."""
import pytest
from jars.microsoft import microsoft_graph


@pytest.fixture
def url_builder():
    """Return a url builder without a baseurl, to test only the created endpoints."""
    return microsoft_graph.UrlBuilder('')
