"""Test fixtures to test the storage interface.

These are intended to check that all storages behave in a similar manor.
"""
import pytest

from tests.test_filesystem import FileSystemSetup
from tests.test_owncloud import OwnCloudSetup
from tests.test_nextcloud import NextCloudSetup
from tests.test_onedrive import OneDriveSetup
from tests.test_onedrive import OneDriveForBussinessSetup
from tests.test_dropbox import DropboxSetup
from tests.test_googledrive import GoogleDriveSetup
from tests.test_office_365 import Office365Setup

STORAGE_SETUPS = [OwnCloudSetup,
                  NextCloudSetup,
                  OneDriveSetup,
                  OneDriveForBussinessSetup,
                  DropboxSetup,
                  GoogleDriveSetup,
                  FileSystemSetup,
                  Office365Setup]

SETUP_IDS = [setup.NAME for setup in STORAGE_SETUPS]


@pytest.fixture(params=STORAGE_SETUPS,
                ids=SETUP_IDS)
def storage_test_setup(request):
    """Collect all StorageSetups into one fixture."""
    return request.param()
