"""Owncloud specific tests.
"""
import json
import logging
import os
import tempfile

import mock
import pytest
import requests_mock

import jars.owncloud
from jars import SharedFolder
from jars.owncloud import (OwnCloud, ShareInfo, SHARES_INFO)
from tests.setup import SetupStorage

from .test_storage import InitStorage, mock_event_sink

TEST_SERVER = os.environ.get('CC_NEXTCLOUD_TEST_SERVER',
                             'http://nextcloud/remote.php/webdav/')


SHARED_WITH = '<?xml version="1.0"?>\
<ocs>\
 <meta>\
  <status>ok</status>\
  <statuscode>100</statuscode>\
  <message/>\
 </meta>\
 <data>\
  <element>\
   <id>1253</id>\
   <item_type>folder</item_type>\
   <item_source>205713</item_source>\
   <parent/>\
   <share_type>0</share_type>\
   <share_with>CrossCloudCI.5</share_with>\
   <file_source>205713</file_source>\
   <file_target>/a</file_target>\
   <path>/a</path>\
   <permissions>31</permissions>\
   <stime>1487599080</stime>\
   <expiration/>\
   <token/>\
   <storage>38</storage>\
   <mail_send>0</mail_send>\
   <uid_owner>test</uid_owner>\
   <storage_id>home::test</storage_id>\
   <file_parent>134588</file_parent>\
   <share_with_displayname>CroSSclUOdci.5</share_with_displayname>\
   <displayname_owner>test</displayname_owner>\
  </element>\
  <element>\
   <id>1255</id>\
   <item_type>folder</item_type>\
   <item_source>205721</item_source>\
   <parent/>\
   <share_type>0</share_type>\
   <share_with>croSscLoudcI.5</share_with>\
   <file_source>205721</file_source>\
   <file_target>/c</file_target>\
   <path>/b/c</path>\
   <permissions>31</permissions>\
   <stime>1487599124</stime>\
   <expiration/>\
   <token/>\
   <storage>38</storage>\
   <mail_send>0</mail_send>\
   <uid_owner>test</uid_owner>\
   <storage_id>home::test</storage_id>\
   <file_parent>205720</file_parent>\
   <share_with_displayname>crosscloudci.5</share_with_displayname>\
   <displayname_owner>test</displayname_owner>\
  </element>\
 </data>\
</ocs>'

SHARED_BY = '<?xml version="1.0"?>\
<ocs>\
 <meta>\
  <status>ok</status>\
  <statuscode>100</statuscode>\
  <message/>\
 </meta>\
 <data>\
  <element>\
   <id>1256</id>\
   <item_type>folder</item_type>\
   <item_source>205724</item_source>\
   <item_target>/205724</item_target>\
   <parent/>\
   <share_type>0</share_type>\
   <share_with>test</share_with>\
   <uid_owner>crosscloudci.5</uid_owner>\
   <file_source>205724</file_source>\
   <path>files/test</path>\
   <file_target>/test</file_target>\
   <permissions>31</permissions>\
   <stime>1487602331</stime>\
   <expiration/>\
   <token/>\
   <storage>37</storage>\
   <mail_send>0</mail_send>\
   <storage_id>home::crosscloudci.5</storage_id>\
   <file_parent>134546</file_parent>\
   <share_with_displayname>test</share_with_displayname>\
   <displayname_owner>crosscloudci.5</displayname_owner>\
  </element>\
 </data>\
</ocs>'


class OwnCloudSetup(SetupStorage):
    """Properties required to initialize a nexcloud test."""
    STORAGE_CLASS = OwnCloud
    NAME = 'owncloud'

    @property
    def init_params(self):
        """Parameters used to initialize the STORGAE_CLASS"""
        token = json.dumps({'server': TEST_SERVER,
                            'username': 'testuser',
                            'password': 'testpass'})

        return {'storage_id': self.NAME,
                'event_sink': self.mock_event_sink,
                'storage_cache_dir': None,
                'storage_cred_reader': lambda: token,
                'storage_cred_writer': None,
                'polling_interval': 4}


def init_owncloud():
    """Initialize the ownloud/nextcloud for the testsuite."""
    fmt = '{levelname:^5} | {filename:^15.15} | {funcName:^20.20} | {message}'

    logging.basicConfig(level=logging.INFO,
                        format=fmt,
                        style='{')
    logging.getLogger("jars.owncloud").setLevel(logging.DEBUG)
    logging.getLogger("jars.webdav").setLevel(logging.DEBUG)
    logging.getLogger("jars").setLevel(logging.INFO)
    logging.getLogger("bushn").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    event_sink = mock_event_sink()
    token = json.dumps(
        {'server': TEST_SERVER,
         'username': 'testuser',
         'password': 'testpass'})

    owncloud = OwnCloud(storage_id='owncloud',
                        event_sink=event_sink,
                        storage_cache_dir=None,
                        storage_cred_reader=lambda: token,
                        storage_cred_writer=None,
                        polling_interval=4)
    owncloud.check_capabilities()
    owncloud.update()

    return InitStorage(storage=owncloud, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=False, is_executed=True, finalizer=None)


def test_prepare_url():
    """Test owncloud url structure.

    Test that owncloud urls are prepared in the right way to reflect
    the owncloud webdav suffix.
    """
    # suffix already there
    url = "http://tools:8080/remote.php/webdav/"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == url[:-1]

    # no suffix but trailing slash
    url = "http://owncloud.crosscloud.me/"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == "http://owncloud.crosscloud.me/remote.php/webdav"

    # no suffix and no trailing slash
    url = "http://owncloud.crosscloud.me"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == "http://owncloud.crosscloud.me/remote.php/webdav"

    # no protocol
    url = "owncloud.crosscloud.me"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == "https://owncloud.crosscloud.me/remote.php/webdav"

    # no protocol but slash
    url = "owncloud.crosscloud.me/"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == "https://owncloud.crosscloud.me/remote.php/webdav"

    # no protocol and ip
    url = "127.0.0.1"
    sanitized_url = jars.owncloud.prepare_url(url)
    assert sanitized_url == "https://127.0.0.1/remote.php/webdav"


def test_get_shared_folders():
    """Test if the get_shared_folder.

    Return the correct lists based on different internal model
    structures. This test is also valid for NextCloud,
    would only need to create a NextCloud item instead.
    """
    suffix = '@test'
    assert_structure = {SharedFolder(path=('a', ),
                                     share_id='205713' + suffix,
                                     sp_user_ids=('test' + suffix,
                                                  'crosscloudci.5' + suffix)),
                        SharedFolder(path=('b', 'c'),
                                     share_id='205721' + suffix,
                                     sp_user_ids=('test' + suffix,
                                                  'crosscloudci.5' + suffix)),
                        SharedFolder(path=('test', ),
                                     share_id='205724' + suffix,
                                     sp_user_ids=('test' + suffix, ))}
    temp_dir = tempfile.mkdtemp()
    storage = jars.owncloud.OwnCloud(event_sink=mock.MagicMock(),
                                     storage_id='storage_id',
                                     storage_cache_dir=str(temp_dir),
                                     storage_cred_writer=mock.MagicMock(),
                                     storage_cred_reader=lambda:
                                     '{"password": "test", "server": '
                                     '"https://test/remote.php/webdav/",'
                                     '"username": "test"}')
    with requests_mock.Mocker() as mocked_request:
        mocked_request.get('https://test/ocs/v1.php/apps/files_sharing/api/v1/shares',
                           text=SHARED_WITH,
                           complete_qs=True)
        mocked_request.get(
            'https://test/ocs/v1.php/apps/files_sharing/api'
            '/v1/shares?shared_with_me=true',
            text=SHARED_BY,
            complete_qs=True)
        assert storage.get_shared_folders() == assert_structure


# pylint: disable=redefined-outer-name
@pytest.fixture
def share_infos():
    """A list of ShareInfo named tuples used to determine the shared state of paths."""
    return set([ShareInfo(path='one/two',
                          share_id='My_share_id',
                          sp_user_ids=('peter@monkeyland.de', 'ray@sound.io'),
                          share_type='2'),

                ShareInfo(path='one/nine',
                          share_id='My_share_id2',
                          sp_user_ids=('one@me.de', 'ray@sound.io'),
                          share_type='1')
                ])


def test_shares_info_reloaded(mocker, share_infos):
    """Ensure that SHARES_INFO is loaded into the shares_info property."""
    storage_test_setup = OwnCloudSetup()

    # The tree loaded from cache should contain the share info
    tree = OwnCloudSetup.NODE_CLASS(None)
    tree.props[SHARES_INFO] = share_infos

    # Return that tree when load model is called in the base.__init__()
    with mocker.patch('jars.load_model', return_value=tree):
        init_params = storage_test_setup.init_params
        storage = storage_test_setup.STORAGE_CLASS(**init_params)

    # Ensure that the shares_info is the same
    # -> no unnessesary resettings of Etags in check_for_changes.
    assert storage.shares_info - share_infos == set()
