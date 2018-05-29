"""This module is inteded to make it easy to write many tests for url_builder.

The input and expected output is pulled from url_builder.yaml to poulate the test.
"""
import pytest
from tests.param_helpers import read_conf

PARAM_KEYS = 'method, expected, args, kwargs'
PARAM_ARGS = {'conf_file_name': 'url_builder.yaml',
              'test_file': __file__}


@pytest.mark.parametrize(PARAM_KEYS, read_conf(**PARAM_ARGS))
def test_urls(method, expected, args, kwargs, url_builder):
    """Test the various methods of the url builder."""
    assert url_builder.__getattribute__(method)(*args, **kwargs) == expected
