"""Test nextcloud implementation.
* The storage tests run against the docker images which are spun up on the CI.
See `.gitlab-ci`

To run the tests locally:
* see `tools/nextcloud-env/README.md` how to start docker-compose
* to point the tests at the server run:
    `$ export CC_NEXTCLOUD_SERVER='http://localhost/remote.php/webdav/'`

* and invoke the tests:
    `$ py.test tests/test_storage.py -k 'nextcloud' -s -vx`
"""

import json
import logging
import os

from jars.owncloud import NextCloud
from tests.test_owncloud import OwnCloudSetup

from .test_storage import InitStorage, mock_event_sink

TEST_SERVER = os.environ.get('CC_NEXTCLOUD_TEST_SERVER',
                             'http://nextcloud/remote.php/webdav/')


class NextCloudSetup(OwnCloudSetup):
    """Properties required to initialize a nexcloud test.

    Since Nextcloud is based on Owncloud. the setup is also pretty similar.
    """
    STORAGE_CLASS = NextCloud
    NAME = 'nextcloud'


def init_nextcloud():
    """Initialize the nextcloud for the testsuite.

    found in `tools/nextcloud-env`
    """
    fmt = '{levelname:^5} | {filename:^15.15} | {funcName:^20.20} | {message}'

    logging.basicConfig(level=logging.INFO,
                        format=fmt,
                        style='{')
    logging.getLogger("jars.nextcloud").setLevel(logging.DEBUG)
    logging.getLogger("jars.owncloud").setLevel(logging.DEBUG)
    logging.getLogger("jars.webdav").setLevel(logging.DEBUG)
    logging.getLogger("bushn").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    event_sink = mock_event_sink()
    token = json.dumps(
        {'server': TEST_SERVER,
         'username': 'testuser',
         'password': 'testpass'})

    nextcloud = NextCloud(storage_id='nextcloud',
                          event_sink=event_sink,
                          storage_cache_dir=None,
                          storage_cred_reader=lambda: token,
                          storage_cred_writer=None,
                          polling_interval=4)
    nextcloud.check_capabilities()
    nextcloud.update()
    return InitStorage(storage=nextcloud, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=False, is_executed=True, finalizer=None)
