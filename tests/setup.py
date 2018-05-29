"""A class to encapulate and simplify the test setup for testing jars."""

import os
import logging
from .test_storage import mock_event_sink, cred_reader, cred_writer, SETTINGS_DIR
import bushn

logger = logging.getLogger(__name__)


class SetupStorage:
    """BassClass of Test setups."""
    NAME = None
    NODE_CLASS = bushn.Node
    ROOT_INIT_PARAMS = {'name': None}

    def __init__(self):
        self.mock_event_sink = mock_event_sink()

    @property
    def init_params(self):
        """Parameters used to initialize the the storage"""

        return {'storage_id': self.NAME,
                'event_sink': self.mock_event_sink,
                'storage_cache_dir': None,
                'storage_cred_reader': self.mock_cred_reader,
                'storage_cred_writer': self.mock_cred_writer}

    @property
    def settings_file(self):
        """Path to file in ~/.cc_test_config/ which contains the token."""
        assert self.NAME, 'Setup %s must have NAME set' % self.__class__.__name__
        tokenfile = '_'.join([self.NAME, 'token'])
        return os.path.join(SETTINGS_DIR, tokenfile)

    def mock_cred_writer(self, item):
        """Write the credentials to the settings_file"""
        return cred_writer(self.settings_file, item)

    def mock_cred_reader(self):
        """Read the credentials from the settings_file"""
        assert os.path.exists(self.settings_file), \
            'No token found at %s' % self.settings_file
        return cred_reader(self.settings_file)
