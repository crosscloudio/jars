"""Test Google Drive only functionality"""
import io
import urllib


import dateutil
import pytest
import requests
import requests_mock
from mock import ANY, MagicMock, Mock

import bushn
from bushn import DELETE, IndexingNode, Node, NodeChange
from jars import (CurrentlyNotPossibleError, InvalidOperationError,
                  SevereError, SharedFolder)
from jars.googledrive import (GoogleDrive, gdrive_error_mapper,
                              gdrive_to_node_props, transform_gdrive_change)
from tests.setup import SetupStorage
from tests.test_storage import (assert_expected_calls_in_timeout,
                                assert_expected_calls_not_in_timeout,
                                delete_all_files, init_googledrive,
                                reset_event_sink, wait_for_events)


class GoogleDriveSetup(SetupStorage):
    """Properties required to initialize a GoogleDrive test."""
    STORAGE_CLASS = GoogleDrive
    NODE_CLASS = bushn.IndexingNode
    NAME = 'GoogleDrive'
    ROOT_INIT_PARAMS = {'name': None,
                        'indexes': ['_id']
                        }

# https://gitlab.crosscloud.me/CrossCloud/client/issues/361
# - Create a shared folder
# - Upload a file to this shared folder
# - Another user deletes this file in the shared folder

CHANGE_SHARED_FOLDER_GUEST_DELETE = (
    {
        'file':
            {'createdTime': '2016-12-02T08:58:18.943Z',
             'explicitlyTrashed': False,
             'fileExtension': 'txt',
             'fullFileExtension': 'txt',
             'headRevisionId': '0B6v1u6D4l2FGSlM3ZU5ENkluYk80emQzUjhrSEZhbFNYMTZZPQ',
             'id': '0B6v1u6D4l2FGUDY0YnNPUmE1RlE',
             'kind': 'drive#file',
             'mimeType': 'text/plain',
             'md5Checksum': '43cdd3c50abe79a06ffc1df0dc05f3f4',
             'modifiedTime': '2016-12-02T08:58:18.943Z',
             'name': 'Notes.txt',
             'originalFilename': 'Notes.txt',
             'ownedByMe': True,
             'quotaBytesUsed': '37',
             'shared': False,
             'size': '37',
             'spaces': ['drive'],
             'trashed': False,
             'version': '277349',
             'viewedByMe': False,
             'viewersCanCopyContent': True,
             'writersCanShare': True},
        'fileId': '0B6v1u6D4l2FGUDY0YnNPUmE1RlE',
        'kind': 'drive#change',
        'removed': False,
        'time': '2016-12-02T08:59:32.085Z'},
    [NodeChange(action='DELETE', parent_id=None, name=None,
                props={'_id': '0B6v1u6D4l2FGUDY0YnNPUmE1RlE'})])

# Add a file to Google Drive
CHANGE_ADD_FILE = (
    {
        'file': {
            'createdTime': '2016-12-02T11:50:21.968Z',
            'explicitlyTrashed': False,
            'fileExtension': 'docx',
            'fullFileExtension': 'docx',
            'hasThumbnail': False,
            'headRevisionId': '0B6v1u6D4l2FGSFlKWGtDZnNmOW9qbUw2TkhTK1dXOGxwTDZVPQ',
            'id': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
            'isAppAuthorized': True,
            'kind': 'drive#file',
            'md5Checksum': 'd41d8cd98f00b204e9800998ecf8427e',
            'mimeType': 'application/vnd.openxmlformats-officedocument.'
                        'wordprocessingml.document',
            'modifiedTime': '2016-12-02T11:50:21.968Z',
            'name': 'New Microsoft Word Document.docx',
            'originalFilename': 'New Microsoft Word Document.docx',
            'ownedByMe': True,
            'parents': ['0AKv1u6D4l2FGUk9PVA'],
            'quotaBytesUsed': '0',
            'shared': False,
            'size': '0',
            'trashed': False},
        'fileId': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
        'kind': 'drive#change',
        'removed': False,
        'time': '2016-12-02T11:50:22.130Z'},
    [NodeChange(action='UPSERT',
                parent_id='0AKv1u6D4l2FGUk9PVA',
                name='New Microsoft Word Document.docx',
                props={'size': 0,
                       'modified_date': dateutil.parser.parse('2016-12-02T11:50:21.968Z'),
                       '_id': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
                       'shared': False,
                       'is_dir': False,
                       'version_id': 'd41d8cd98f00b204e9800998ecf8427e',
                       '_shared_with': set()})]
)

# Add a file to Google Drive
CHANGE_ADD_FILE_MULTIPLE_PARENTS = (
    {
        'file': {
            'createdTime': '2016-12-02T11:50:21.968Z',
            'explicitlyTrashed': False,
            'fileExtension': 'docx',
            'fullFileExtension': 'docx',
            'hasThumbnail': False,
            'headRevisionId': '0B6v1u6D4l2FGSFlKWGtDZnNmOW9qbUw2TkhTK1dXOGxwTDZVPQ',
            'id': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
            'isAppAuthorized': True,
            'kind': 'drive#file',
            'md5Checksum': 'd41d8cd98f00b204e9800998ecf8427e',
            'mimeType': 'application/vnd.openxmlformats-officedocument.'
                        'wordprocessingml.document',
            'modifiedTime': '2016-12-02T11:50:21.968Z',
            'name': 'New Microsoft Word Document.docx',
            'originalFilename': 'New Microsoft Word Document.docx',
            'ownedByMe': True,
            'parents': ['0AKv1u6D4l2FGUk9PVA', '0AKv1u6D4l2FGUk9PVB'],
            'quotaBytesUsed': '0',
            'shared': False,
            'size': '0',
            'trashed': False},
        'fileId': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
        'kind': 'drive#change',
        'removed': False,
        'time': '2016-12-02T11:50:22.130Z'},
    [NodeChange(action='UPSERT',
                parent_id='0AKv1u6D4l2FGUk9PVA',
                name='New Microsoft Word Document.docx',
                props={'size': 0,
                       'modified_date': dateutil.parser.parse('2016-12-02T11:50:21.968Z'),
                       '_id': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
                       'shared': False,
                       'is_dir': False,
                       'version_id': 'd41d8cd98f00b204e9800998ecf8427e',
                       '_shared_with': set()}),
     NodeChange(action='UPSERT',
                parent_id='0AKv1u6D4l2FGUk9PVB',
                name='New Microsoft Word Document.docx',
                props={'size': 0,
                       'modified_date': dateutil.parser.parse('2016-12-02T11:50:21.968Z'),
                       '_id': '0B6v1u6D4l2FGM1YxMUJFd2k1eWM',
                       'shared': False,
                       'is_dir': False,
                       'version_id': 'd41d8cd98f00b204e9800998ecf8427e',
                       '_shared_with': set()})]
)

# change for an add folder event
CHANGE_ADD_FOLDER = (
    {'file': {'createdTime': '2016-12-02T14:35:35.758Z',
              'explicitlyTrashed': False,
              'id': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs',
              'isAppAuthorized': False,
              'kind': 'drive#file',
              'mimeType': 'application/vnd.google-apps.folder',
              'modifiedTime': '2016-12-02T14:35:35.758Z',
              'name': 'folder_a',
              'parents': ['0AKv1u6D4l2FGUk9PVA'],
              'quotaBytesUsed': '0',
              'shared': False,
              'trashed': False,
              'version': '277357'},
     'fileId': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs',
     'kind': 'drive#change',
     'removed': False,
     'time': '2016-12-02T14:35:35.811Z'},
    [NodeChange(action='UPSERT',
                parent_id='0AKv1u6D4l2FGUk9PVA',
                name='folder_a',
                props={'size': 0,
                       'modified_date': dateutil.parser.parse('2016-12-02T14:35:35.758Z'),
                       '_id': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs',
                       'shared': False,
                       'is_dir': True,
                       'version_id': 'is_dir',
                       '_shared_with': set()})]
)

# Change for a folder deletion event
CHANGE_DELETE_FOLDER = (
    {'file': {'createdTime': '2016-12-02T14:35:35.758Z',
              'explicitlyTrashed': True,
              'id': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs',
              'kind': 'drive#file',
              'mimeType': 'application/vnd.google-apps.folder',
              'modifiedTime': '2016-12-02T14:35:35.758Z',
              'name': 'folder_a',
              'parents': ['0AKv1u6D4l2FGUk9PVA'],
              'shared': False,
              'trashed': True,
              'version': '277359'},
     'fileId': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs',
     'kind': 'drive#change',
     'removed': False,
     'time': '2016-12-02T14:45:12.426Z'},
    [NodeChange(action='DELETE', parent_id=None, name=None,
                props={'_id': '0B6v1u6D4l2FGaDl6X3ZGbml1YWs'})]
)

# Change for a file deletione event
CHANGE_DELETE_FILE = (
    {'file': {'createdTime': '2016-12-02T15:17:29.427Z',
              'explicitlyTrashed': True,
              'id': '0B6v1u6D4l2FGWllpd0VEVUM2VWM',
              'kind': 'drive#file',
              'md5Checksum': 'a779114e8574097585d40292da4cddd7',
              'mimeType': 'image/png',
              'modifiedTime': '2016-12-02T15:17:29.427Z',
              'name': 'Capture.PNG',
              'originalFilename': 'Capture.PNG',
              'parents': ['0AKv1u6D4l2FGUk9PVA'],
              'shared': False,
              'size': '111202',
              'trashed': True},
     'fileId': '0B6v1u6D4l2FGWllpd0VEVUM2VWM',
     'kind': 'drive#change',
     'removed': False,
     'time': '2016-12-02T15:19:01.665Z'},
    [NodeChange(action='DELETE', parent_id=None, name=None,
                props={'_id': '0B6v1u6D4l2FGWllpd0VEVUM2VWM'})])


@pytest.mark.parametrize('input_change, expected',
                         [CHANGE_SHARED_FOLDER_GUEST_DELETE,
                          CHANGE_ADD_FILE,
                          CHANGE_ADD_FOLDER,
                          CHANGE_DELETE_FOLDER,
                          CHANGE_DELETE_FILE,
                          CHANGE_ADD_FILE_MULTIPLE_PARENTS])
def test_transform_changes(input_change, expected):
    """Uses a change input and checks if this is mapped to the correct output.

    :param input_change: the json change
    :param expected: expected result
    """
    actual = transform_gdrive_change(input_change)
    print(actual)
    print(expected)
    assert expected == actual


def test_google_drive_error_decorator_403_userRateLimitExceeded():
    """Tests the ErrorMapper decorator.

    Error: 403 userRateLimitExceeded
    https://developers.google.com/drive/v3/web/handle-errors#403_user_rate_limit_exceeded
    This should be mapped to a CurrentlyNotPossibleError
    :return:
    """
    with pytest.raises(CurrentlyNotPossibleError):
        resp_data = '{"error": {"errors": [{"domain": "usageLimits", ' \
                    '"reason": "userRateLimitExceeded", ' \
                    '"message": "User rate limit exceeded."}],' \
                    ' "code": 403, "message": "User rate limit exceeded."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_rateLimitExceeded():
    """Tests the ErrorMapper decorator.

    Error: 403 rateLimitExceeded
    https://developers.google.com/drive/v3/web/handle-errors#403_rate_limit_exceeded
    This should be mapped to a CurrentlyNotPossibleError
    :return:
    """
    with pytest.raises(CurrentlyNotPossibleError):
        resp_data = '{"error": {"errors": [{"domain": "usageLimits",' \
                    '"message": "Rate Limit Exceeded",' \
                    '"reason": "rateLimitExceeded"}],' \
                    ' "code": 403, "message": "User rate limit exceeded."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_sharingRateLimitExceeded():
    """Tests the ErrorMapper decorator.

    Error: 403 sharingRateLimitExceeded
    https://developers.google.com/drive/v3/web/handle-errors#403_sharing
    _rate_limit_exceeded
    This should be mapped to a CurrentlyNotPossibleError
    :return:
    """
    with pytest.raises(CurrentlyNotPossibleError):
        resp_data = '{"error": {"errors": [{"domain": "global",' \
                    '"message": "Rate limit exceeded. User message: ' \
                    'These item(s) could not be shared because a rate limit was ' \
                    'exceeded: filename",' \
                    '"reason": "sharingRateLimitExceeded"}],' \
                    ' "code": 403, "message": "User rate limit exceeded."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_appNotAuthorizedToFile():
    """Test the ErrorMapper decorator.

    Error: 403 appNotAuthorizedToFile
    https://developers.google.com/drive/v3/web/handle-errors#403_the_user
    _has_not_granted_the_app_appid_verb_access_to_the_file_fileid
    This should be mapped to a InvalidOperationError
    :return:
    """
    with pytest.raises(InvalidOperationError):
        resp_data = '{"error": {"errors": [{"domain": "global",' \
                    '"reason": "appNotAuthorizedToFile","message":' \
                    '"The user has not granted the app {appId} {verb} access to the' \
                    'file {fileId}."}],"code": 403,' \
                    '"message": "The user has not granted the app {appId}' \
                    '{verb} access to the file {fileId}."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_insufficientFilePermissions():
    """Test the ErrorMapper decorator.

    Error: 403 insufficientFilePermissions
    https://developers.google.com/drive/v3/web/handle-errors#403_the_user
    _does_not_have_sufficient_permissions_for_file_fileid
    This should be mapped to a InvalidOperationError
    :return:
    """
    with pytest.raises(InvalidOperationError):
        resp_data = '{"error": {"errors": [{"domain": "global",' \
                    '"reason": "insufficientFilePermissions",' \
                    '"message": "The user does not have sufficient ' \
                    'permissions for file {fileId}."}],"code": 403,' \
                    '"message": "The user does not have sufficient' \
                    'permissions for file {fileId}."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_domainPolicy():
    """Test the ErrorMapper decorator.

    Error: 403 domainPolicy
    https://developers.google.com/drive/v3/web/handle-errors#403_app_with_id_appid
    _cannot_be_used_within_the_authenticated_users_domain
    This should be mapped to a InvalidOperationError
    :return:
    """
    with pytest.raises(InvalidOperationError):
        resp_data = '{"error": {"errors": [{"domain": "global",' \
                    '"reason": "domainPolicy", "message":' \
                    '"The domain administrators have disabled Drive apps."}],' \
                    '"code": 403,' \
                    '"message": "The domain administrators have disabled Drive apps."}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_dailyLimitExceeded():
    """Test the ErrorMapper decorator.

    Error: 403 dailyLimitExceeded
    https://developers.google.com/drive/v3/web/handle-errors#403_daily_limit_exceeded
    This should be mapped to a SevereError because this is caused by our
    Google App API limits -> should be logged to Sentry
    :return:
    """
    with pytest.raises(SevereError):
        resp_data = '{"error": {"errors": [{"domain": "usageLimits",' \
                    '"reason": "dailyLimitExceeded",' \
                    '"message": "Daily Limit Exceeded"}],' \
                    '"code": 403,"message": "Daily Limit Exceeded"}}'
        decorated_function(403, resp_data)


def test_google_drive_error_decorator_403_any():
    """Test the ErrorMapper decorator.

    Error: 403
    :return:
    """
    with pytest.raises(requests.HTTPError):
        resp_data = 'blabla'
        decorated_function(403, resp_data)


@gdrive_error_mapper
def decorated_function(response_code, resp_data):
    """Execute a mocked request which returns a given response_code and response_data."""
    with requests_mock.Mocker() as mocker:
        mocker.get('http://test.com', text=resp_data, status_code=response_code)
        response = requests.get('http://test.com')
        response.raise_for_status()


def test_gdrive_to_node_props_shared():
    """Test the gdrive_to_node_props function for a response of a shared file."""
    props = {
        "id": "0BzdHhvKs9uEFdGtHUU9lc3lHLVk",
        "name": "cv.pdf",
        "mimeType": "application/pdf",
        "trashed": False,
        "parents": [
            "0BzdHhvKs9uEFWld6SV92Zjg0dnc"
        ],
        "shared": True,
        "modifiedTime": "2017-02-07T12:58:57.235Z",
        "permissions": [
            {
                "emailAddress": "julian@crosscloud.net",
                "id": 12
            },
            {
                "emailAddress": "jakob@crosscloud.net",
                "id": 13
            },
            {
                "emailAddress": "christoph@crosscloud.net",
                "id": 14
            },
            {
                "emailAddress": "gabriele@crosscloud.net",
                "id": 15
            }
        ],
        "md5Checksum": "361d888d9e228183a4a7ba97797a0002",
        "size": "14313"
    }
    node_props = gdrive_to_node_props(props)
    assert node_props['_id'] == props['id']
    assert node_props['shared'] is True
    assert node_props['size'] == int(props['size'])
    assert node_props['_shared_with'] == {12, 13, 14, 15}


def test_gdrive_to_node_props_not_shared():
    """Test the gdrive_to_node_props function for a response of a not shared file."""
    props = {
        "id": "0BzdHhvKs9uEFdGtHUU9lc3lHLVk",
        "name": "cv.pdf",
        "mimeType": "application/pdf",
        "trashed": False,
        "parents": [
            "0BzdHhvKs9uEFWld6SV92Zjg0dnc"
        ],
        "shared": False,
        "modifiedTime": "2017-02-07T12:58:57.235Z",
        "permissions": [
            {
                "emailAddress": "jakob@crosscloud.net"
            }
        ],
        "md5Checksum": "361d888d9e228183a4a7ba97797a0002",
        "size": "14313"
    }
    node_props = gdrive_to_node_props(props)
    assert node_props['_id'] == props['id']
    assert node_props['shared'] is False
    assert node_props['size'] == int(props['size'])


def test_get_shared_folders():
    """Test the return the correct lists based on different internal model structures."""
    gdrive = MagicMock()
    gdrive.model = Node(name=None)

    # No shared folder
    folder_a = gdrive.model.add_child('folder_a', {'shared': False,
                                                   '_id': 'id_of_folder_a',
                                                   'other': 'stuff'})
    assert GoogleDrive.get_shared_folders(gdrive) == []

    # one shared folder
    folder_b = folder_a.add_child('folder_b', {'shared': True,
                                               '_id': 'id_of_folder_b',
                                               'other': 'stuff of b',
                                               '_shared_with':
                                                   {'test1@test.com', 'test2@test.com'}})

    shared_folder_b = SharedFolder(path=['folder_a', 'folder_b'],
                                   share_id='id_of_folder_b',
                                   sp_user_ids={'test1@test.com', 'test2@test.com'})
    assert GoogleDrive.get_shared_folders(gdrive) == [shared_folder_b]

    # two shared folders but one is the child of the other
    folder_b.add_child('folder_c', {'shared': True,
                                    '_id': 'id_of_folder_c',
                                    'other': 'stuff of c',
                                    '_shared_with':
                                        {'test1@test.com', 'test2@test.com'}})
    assert GoogleDrive.get_shared_folders(gdrive) == [shared_folder_b]

    # added a third shared folder
    folder_a.add_child('folder_d', {'shared': True,
                                    '_id': 'id_of_folder_d',
                                    'other': 'stuff of d',
                                    '_shared_with': {'test3@test.com', 'test4@test.com'}})
    shared_folder_d = SharedFolder(path=['folder_a', 'folder_d'],
                                   share_id='id_of_folder_d',
                                   sp_user_ids={'test3@test.com', 'test4@test.com'})
    assert sorted(GoogleDrive.get_shared_folders(gdrive)) == sorted(
        [shared_folder_d, shared_folder_b])


# pylint: disable=protected-access
def test_share_users_handling():
    """Test the handling of a share when users join or leave.

    When users leave or join a share no changes should be applied to the files that are part of
    it. Ensure that the key_subjects of the shared items remains the same during the process for
    all operations.

    This test shares files with crosscloudci.6 and crosscloudci.5. If you are using one of those
    accounts to run this test, it will FAIL!
    """
    gdrive = init_googledrive()

    storage = gdrive.storage
    storage.start_events()

    event_sink = gdrive.event_sink

    expected_calls = []

    delete_all_files(storage=storage, event_sink=event_sink, reset=True)
    # create test file structure
    test_paths = [['shared_folder'], ['shared_folder', 'shared_file']]
    test_content = b'test content'
    assert storage.write(path=['shared_folder', 'shared_file'], file_obj=io.BytesIO(test_content),
                         original_version_id=None, size=len(test_content))

    # wait for events
    wait_for_events(event_sink=event_sink, storage_create=len(test_paths))
    reset_event_sink(event_sink=event_sink)

    shared_folder = storage.model.get_node(['shared_folder'])

    # share the folder
    url = urllib.parse.urljoin(storage.base_url, 'files/' + shared_folder.props['_id'] +
                               '/permissions')

    # Attention! This test will fail if the following or the account further below is
    # the same as the one we are logging in with.
    body = {'emailAddress': 'crosscloudci.6@gmail.com', 'type': 'user', 'role': 'writer'}

    response = storage.oauth_session.post(url, json=body)

    response.raise_for_status()

    # wait_for_events(event_sink=event_sink,storage_modify=1)
    expected_calls.append(('storage_modify', (), {'storage_id': storage.storage_id,
                                                  'path': ['shared_folder'],
                                                  'event_props': {'shared': True,
                                                                  'public_share': False,
                                                                  'modified_date': ANY,
                                                                  'version_id': 'is_dir',
                                                                  'share_id': ANY,
                                                                  'size': 0,
                                                                  'is_dir': True}}))
    assert_expected_calls_in_timeout(expected_calls, event_sink)
    reset_event_sink(event_sink=event_sink)

    # We need at least 3 users in the share for this
    body = {'emailAddress': 'crosscloudci.5@gmail.com', 'type': 'user', 'role': 'writer'}

    response = storage.oauth_session.post(url, json=body)
    response.raise_for_status()
    expected_calls = []

    expected_calls.append(('storage_modify', (), {'storage_id': storage.storage_id,
                                                  'path': ['shared_folder'],
                                                  'event_props': {'shared': ANY,
                                                                  'public_share': ANY,
                                                                  'modified_date': ANY,
                                                                  'version_id': ANY,
                                                                  'share_id': DELETE,
                                                                  'size': ANY,
                                                                  'is_dir': ANY}}))
    assert_expected_calls_not_in_timeout(expected_calls, event_sink)


def test_adjust_share_ids():
    """Test adjust_share_ids given different trees."""
    import logging
    logging.basicConfig(level=logging.DEBUG)
    gdrive = Mock(GoogleDrive)
    gdrive.model = IndexingNode(None, indexes=['_id'])
    tree = gdrive.model

    # Empty mergesets should mean no changes
    mergeset = []
    GoogleDrive._adjust_share_ids(gdrive, mergeset)
    assert tree.props == {}

    # if the node is located in the root is not necessary to compare properties with the parent
    child_1 = tree.add_child(name='child_1', props={'_id': 'id_1'})
    mergeset = [NodeChange(action='UPSERT', parent_id=None, name=child_1.name,
                           props=child_1.props)]

    GoogleDrive._adjust_share_ids(gdrive, mergeset)

    assert len(child_1.props) is 1

    # if the file is not located on the root, it should be compared with the parent
    child_1_1 = child_1.add_child(name='child_1_1', props={'_id': 'id_1_1'})
    mergeset = [NodeChange(action='UPSERT', parent_id=child_1.props['_id'], name=child_1_1.name,
                           props=child_1_1.props)]

    # shared_with property is the same and no share_id -> nothing happens
    GoogleDrive._adjust_share_ids(gdrive, mergeset)

    assert child_1_1.props == {'_id': 'id_1_1'}

    # child_1_1 shared_with atribute is different than his parent
    child_1_1.props['_shared_with'] = ('random_123',)

    # Now that the mergeset fields are not hardcoded there should not be need for this step
    # mergeset = [
    #         ('UPSERT', 'id_1', 'child_1_1', {'_id': 'id_1_1', '_shared_with': ('random_123',)})
    # ]

    # child_1_1 share_id should be set to child_1_1 _id
    GoogleDrive._adjust_share_ids(gdrive, mergeset)

    assert child_1_1.props['_id'] == child_1_1.props['share_id']

    # same case as above, but child_1 is shared too
    child_1.props['_shared_with'] = ('random_321',)
    mergeset = [
            (NodeChange(action='UPSERT', parent_id=None, name='child_1',
                        props={'_id': 'id_1', '_shared_with': ('random_321',)}))
    ]

    GoogleDrive._adjust_share_ids(gdrive, mergeset)

    assert child_1_1.props['_id'] == child_1_1.props['share_id']
    assert child_1.props['_id'] == child_1.props['share_id']

    # child_1 and child_1_1 are shared with the same users -> same share -> remove child_1_1
    # share_id
    child_1_1.props['_shared_with'] = ('random_321',)
    mergeset = [
            NodeChange(action='UPSERT', parent_id='id_1', name='child_1_1',
                       props={'_id': 'id_1_1', '_shared_with': ('random_321',)})
    ]

    GoogleDrive._adjust_share_ids(gdrive, mergeset)

    assert child_1.props['share_id'] == child_1.props['_id']
    assert child_1_1.props.get('share_id', None) is None

    # DELETEs should be skipped
    mergeset = [NodeChange(action='DELETE', parent_id='id_1', name='child_1_1',
                           props={'_id': 'id_1_1'})]
    GoogleDrive._adjust_share_ids(gdrive, mergeset)
    assert child_1.props['share_id'] == child_1.props['_id']
    assert child_1_1.props.get('share_id', None) is None

    # Merges of nodes that don't exist in our index should also be skipped
    mergeset = [
            NodeChange(action='UPSERT', parent_id='id_1', name='child_1_2',
                       props={'_id': 'id_1_2', '_shared_with': ('random_123',)})
    ]
    GoogleDrive._adjust_share_ids(gdrive, mergeset)
    assert child_1.props['share_id'] == child_1.props['_id']
    assert child_1_1.props.get('share_id', None) is None
