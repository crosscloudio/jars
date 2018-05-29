"""This module contains test setup for sharepoint storage_tests and tests specifically
for sharepoint.
"""
import logging
import os

import filelock
import pytest

from jars import microsoft
from tests.param_helpers import read_conf

from .test_storage import (LOCK_TIMEOUT, SETTINGS_DIR, InitStorage,
                           mock_event_sink)

def init_sharepoint():
    """Return InitStorage namedtuple to be used by the testsuite. """
    # fmt = '{levelname:^5} | {filename:^15.15}{lineno:4d} | {funcName:^15.15} | {message}'
    fmt = '{levelname:^5} | {threadName:^15.15} | {funcName:^15.15} | {message}'

    logging.basicConfig(level=logging.INFO,
        format=fmt,
        style='{')
    logging.getLogger("jars.microsoft").setLevel(logging.DEBUG)
    logging.getLogger("bushn").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    storage_id = 'sharepoint'
    storage_class = microsoft.SharePoint
    event_sink = mock_event_sink()
    settings_file = os.path.join(SETTINGS_DIR, storage_id)

    with open(settings_file, 'r') as file:
        token = file.read()
    lock = filelock.FileLock(settings_file + '.lock')

    # Our Sharepoint server is slow -> double the timeout.
    lock.acquire(timeout=LOCK_TIMEOUT * 2)

    storage = storage_class(event_sink=event_sink,
                            storage_id=storage_id,
                            storage_cred_reader=lambda: token)

    return InitStorage(storage=storage, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=True, is_executed=True, finalizer=lock.release)


PARAM_KEYS = 'method, expected, args, kwargs'
PARAM_ARGS = {'conf_file_name': 'sharepoint_root_urls.yaml',
              'test_file': __file__}

@pytest.mark.parametrize(PARAM_KEYS, read_conf(**PARAM_ARGS))
def test_root_urls(method, expected, args, kwargs):
    """Test the various methods of the url builder.

    For simplicity. the base_url is set to an empty sting, this makes the construncted
    urls shorter and a bit easier to read.
    """
    base_url = ''
    url_builder = microsoft.SharePoint.URL_BUILDER_CLASS(base_url)
    assert url_builder.__getattribute__(method)(*args, **kwargs) == expected


PARAM_ARGS = {'conf_file_name': 'sharepoint_site_urls.yaml',
              'test_file': __file__}

@pytest.mark.parametrize(PARAM_KEYS, read_conf(**PARAM_ARGS))
def test_non_root_urls(method, expected, args, kwargs):
    """Test the various methods of the url builder.

    In this case we include the word site in the base url in order to point all requests
    at a subsite of the Sharepoint instance.
    """
    base_url = 'sites/monkey'
    url_builder = microsoft.SharePoint.URL_BUILDER_CLASS(base_url)
    assert url_builder.__getattribute__(method)(*args, **kwargs) == expected
