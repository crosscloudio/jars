"""Test generic storages against defined interface."""
import logging
import pprint
import webbrowser
import contextlib
import sys
import os
from os.path import expanduser
import io
from collections import namedtuple
import copy
import shutil
import tempfile
# noinspection PyUnresolvedReferences
import time
import threading
from functools import partial
from unittest.mock import MagicMock
from unittest import mock

import pytest
import filelock
import termcolor
import bushn


from jars.utils import ControlFileWrapper

from jars import VersionIdNotMatchingError, IS_DIR, \
    VERSION_ID, FOLDER_VERSION_ID, SHARED, StorageError, casefold_path, METRICS
from jars.oauth_http_server import OAuthHTTPServer
import jars.dropbox as dp
from jars.fs import Filesystem
import jars.webdav
import jars.owncloud

from jars import microsoft
from jars.googledrive import GoogleDrive
from jars.utils import FilterEventSinkWrapper
from tests import any_args, assert_args

# CIFS tests only work on windows.
if os.name == 'nt':
    # pylint: disable=ungrouped-imports
    import jars.fs.cifs

# pylint: disable=invalid-name,too-many-lines,redefined-outer-name

SETTINGS_DIR = os.path.join(expanduser("~"), '.cc_test_config')
logger = logging.getLogger(__name__)

# filename used for all different tests - if you want to test specific cases - change
# this
TEST_FILE_NAME = 'test  äää  111 üüü.txt'
# TEST_FILE_NAME = 'somethingsimple.txt'

# noinspection PyUnresolvedReferences
pytestmark = pytest.mark.network_tests

InitStorage = namedtuple('InitStorage', ['storage', 'event_sink', 'normalized_paths',
                                         'emits_move_events', 'is_executed', 'finalizer'])

# a test should not take longer then 15 minutes
LOCK_TIMEOUT = 900


def obtain_token(storage):
    """ helper to obtain a storage token """

    grant_url = storage.grant_url()
    s = OAuthHTTPServer(grant_url.check_function)

    webbrowser.open(grant_url.grant_url)
    logger.debug('starting webserver and waiting')
    th = threading.Thread(target=s.serve_forever)
    th.start()

    s.done_event.wait()
    logger.debug('auth return')
    _, token, _ = storage.authenticate(grant_url, s.result)
    print(token)
    s.shutdown()


def init_dropbox():
    """Inits dropbox service."""

    db_settings_file = os.path.join(SETTINGS_DIR, 'dropbox_token')

    # ignore test if no config file
    if not os.path.isfile(db_settings_file):
        return InitStorage(storage=None, event_sink=None, normalized_paths=True,
                           emits_move_events=False, is_executed=False, finalizer=None)

    with open(db_settings_file) as file:
        token = file.read()

    lock = filelock.FileLock(db_settings_file + '.lock')
    lock.acquire(timeout=LOCK_TIMEOUT)

    event_sink = mock_event_sink()
    dropbox = dp.Dropbox(storage_id='dropbox',
                         event_sink=event_sink,
                         storage_cache_dir=None,
                         storage_cred_reader=lambda: token,
                         storage_cred_writer=None)

    # init changes
    logger.debug('updating Dropbox model')
    dropbox.update()

    return InitStorage(storage=dropbox, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=False, is_executed=True, finalizer=lock.release)


def init_filesystem():
    """Inits a local filesystem to test."""

    logging.basicConfig(level=logging.DEBUG)

    event_sink = mock_event_sink()

    path = tempfile.mkdtemp()
    # request.addfinalizer(lambda: shutil.rmtree(path))
    logger.debug('initializing filesystem to %s', path)
    filesystem = Filesystem(path, event_sink, 'filesystem')

    def finalizer():
        """ checks if tmpdir is empty and deletes the tempdir """
        cc_tmp_dir = os.path.join(path, Filesystem.TEMPDIR)
        if os.path.isdir(cc_tmp_dir):
            assert os.listdir(cc_tmp_dir) == []
        shutil.rmtree(path)

    # init changes
    return InitStorage(storage=filesystem, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=False, is_executed=True, finalizer=finalizer)


def cred_reader(filename):
    """Read credentials from a token file"""
    try:
        with open(filename, 'r') as token_file:
            return token_file.read()
    except BaseException:
        return None


def cred_writer(filename, item):
    """Write credentals to a token file."""
    with open(filename, 'w') as token_file:
        return token_file.write(item)


def init_cifs(cls=False, tokenfile='cifs_token'):
    """Initialize CIFS storage setup for the testsuite."""
    cls = jars.fs.cifs.CifsFileSystem

    if os.name != "nt":
        logger.critical("CIFS Tests currently only work on windows.")
        return InitStorage(storage=None, event_sink=None, normalized_paths=False,
                           emits_move_events=True, is_executed=False, finalizer=None)

    logging.basicConfig(level=logging.DEBUG)

    cifs_settings_file = os.path.join(SETTINGS_DIR, tokenfile)
    logger.debug("Trying to read credentials from '%s'", cifs_settings_file)

    cifs_cred_writer = partial(cred_writer, cifs_settings_file)
    cifs_cred_reader = partial(cred_reader, cifs_settings_file)

    # get old tokens
    token_json = cifs_cred_reader()
    logger.debug(token_json)
    if not token_json:
        logger.info("Skipping CIFS Tests. No credentials found!")
        return InitStorage(storage=None, event_sink=None, normalized_paths=False,
                           emits_move_events=True, is_executed=False, finalizer=None)

    lock = filelock.FileLock(cifs_settings_file + '.lock')
    lock.acquire(timeout=LOCK_TIMEOUT)

    event_sink = mock_event_sink()
    storage = cls(event_sink=event_sink,
                  storage_id='cifs',
                  storage_cache_dir=None,
                  storage_cred_writer=cifs_cred_writer,
                  storage_cred_reader=cifs_cred_reader,
                  polling_interval=1)
    storage.update()

    return InitStorage(storage=storage, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=True, is_executed=True, finalizer=lock.release)


def init_onedrive(cls=microsoft.OneDrive, tokenfile='onedrive_token'):
    """Inits the webdav for the testsuite."""

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger(
        'requests_oauthlib.oauth2_session').setLevel(logging.ERROR)

    onedrive_settings_file = os.path.join(SETTINGS_DIR, tokenfile)

    onedrive_cred_writer = partial(cred_writer, onedrive_settings_file)
    ondrive_cred_reader = partial(cred_reader, onedrive_settings_file)

    # get old tokens
    token_json = ondrive_cred_reader()
    logger.debug(token_json)
    if not token_json:
        return InitStorage(storage=None, event_sink=None, normalized_paths=False,
                           emits_move_events=True, is_executed=False, finalizer=None)

    lock = filelock.FileLock(onedrive_settings_file + '.lock')
    lock.acquire(timeout=LOCK_TIMEOUT)

    event_sink = mock_event_sink()
    storage = cls(event_sink=event_sink,
                  storage_id='ondrive',
                  storage_cache_dir=None,
                  storage_cred_writer=onedrive_cred_writer,
                  storage_cred_reader=ondrive_cred_reader,
                  polling_interval=1)

    storage.update()

    return InitStorage(storage=storage, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=True, is_executed=True, finalizer=lock.release)


def init_onedrive_business():
    """inits onedrive for business."""
    return init_onedrive(microsoft.OneDriveBusiness, 'onedrive_business_token')


def init_office365_groups():
    """Setup a single group for office.

    This is very similar to init_onedrive_business, but needs the group set
    prior to calling storage.update().

    Note: The group CI_Playgroup is used, of which the account must be a owner.
    """
    cls = microsoft.office365.SingleOffice365Group
    cls.API_CLASS = microsoft.microsoft_graph.Office365Api
    tokenfile = 'office365_token'
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger(
        'requests_oauthlib.oauth2_session').setLevel(logging.ERROR)

    onedrive_token_file = os.path.join(SETTINGS_DIR, tokenfile)

    onedrive_cred_writer = partial(cred_writer, onedrive_token_file)
    ondrive_cred_reader = partial(cred_reader, onedrive_token_file)

    # get old tokens
    token_json = ondrive_cred_reader()
    logger.debug(token_json)
    if not token_json:
        return InitStorage(storage=None, event_sink=None, normalized_paths=False,
                           emits_move_events=True, is_executed=False, finalizer=None)

    lock = filelock.FileLock(onedrive_token_file + '.lock')
    lock.acquire(timeout=LOCK_TIMEOUT)

    event_sink = mock_event_sink()
    storage = cls(event_sink=event_sink,
                  storage_id='ondrive',
                  storage_cache_dir=None,
                  storage_cred_writer=onedrive_cred_writer,
                  storage_cred_reader=ondrive_cred_reader,
                  polling_interval=1)

    groups = storage.list_avaliable_groups()
    ci_playgroud = [group['id'] for group in groups
                    if group['displayName'] == 'CI_playgroud'][0]
    logger.info('using ci_playground group with id: %s', ci_playgroud)
    storage.group_id = ci_playgroud

    storage.update()

    return InitStorage(storage=storage, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=True, is_executed=True, finalizer=lock.release)


def init_googledrive():
    """Inits the webdav for the testsuite."""

    logging.basicConfig(level=logging.WARNING)

    # logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger(
        'jars.googledrive').setLevel(logging.DEBUG)
    # logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger(
        'requests_oauthlib.oauth2_session').setLevel(logging.ERROR)

    gdrive_settings_file = os.path.join(SETTINGS_DIR, 'gdrive_token')

    # noinspection PyBroadException
    # pylint: disable=bare-except

    gdrive_cred_writer = partial(cred_writer, gdrive_settings_file)
    gdrive_cred_reader = partial(cred_reader, gdrive_settings_file)

    # get old tokens
    token_json = gdrive_cred_reader()

    if not token_json:
        return InitStorage(storage=None, event_sink=None, normalized_paths=False,
                           emits_move_events=True, is_executed=False, finalizer=None)

    lock = filelock.FileLock(gdrive_settings_file + '.lock')
    lock.acquire(timeout=LOCK_TIMEOUT)

    event_sink = mock_event_sink()
    storage = GoogleDrive(event_sink=event_sink,
                          storage_id='googledrive',
                          storage_cache_dir=None,
                          storage_cred_writer=gdrive_cred_writer,
                          storage_cred_reader=gdrive_cred_reader,
                          polling_interval=1)

    storage.update()

    return InitStorage(storage=storage, event_sink=event_sink, normalized_paths=False,
                       emits_move_events=True, is_executed=True, finalizer=lock.release)

# def test_online_offline(init_storage_test_without_files_events):
#     storage = init_storage_test_without_files_events.storage
#     event_sink = init_storage_test_without_files_events.event_sink
#
#     with GoOffline():
#         expected = ['storage_offline', (), ()]
#         assert_expected_calls_in_timeout(expected, event_sink)
#
#     expected = ['storage_online', (), ()]
#     assert_expected_calls_in_timeout(expected, event_sink)


@pytest.mark.crud
def test_has_display_name(init_storage_test_without_files):
    """Test if the storage has a display name set."""
    storage = init_storage_test_without_files.storage

    assert storage.storage_name is not None
    assert storage.storage_display_name is not None


@pytest.mark.crud
def test_overwrite(init_storage_test_without_files):
    """Tests if write can overwrite files."""

    storage = init_storage_test_without_files.storage

    content1 = io.BytesIO(b'the content 1')
    version_id = storage.write(
        ["Hello.txt"], content1, size=len(content1.getvalue()))
    logger.info('wrote with version id %s', version_id)

    content2 = io.BytesIO(b'the content 12')
    newer_v_id = storage.write(["Hello.txt"], content2, version_id,
                               size=len(content2.getvalue()))
    logger.info('updated with version id %s', newer_v_id)

    with pytest.raises(VersionIdNotMatchingError):
        logger.info('updating with old version id %s', version_id)
        content2 = io.BytesIO(b'the content 123')
        storage.write(["Hello.txt"], content2, version_id,
                      size=len(content2.getvalue()))

    # checking immunity
    check_storage_event_reference_immunity(
        event_sink=init_storage_test_without_files.event_sink, storage=storage)


@pytest.mark.crud
def test_read_write(init_storage_test_without_files):
    """Simple read and write test."""
    storage = init_storage_test_without_files.storage

    data = b'the content 1'
    content1 = io.BytesIO(data)
    version_id = storage.write(["Hello"], content1, size=len(data))
    assert storage.open_read(
        ["Hello"], version_id).read() == content1.getvalue()


@pytest.mark.crud
def test_read_with_clear_model(init_storage_test_without_files):
    """Simple read and write test."""
    storage = init_storage_test_without_files.storage

    content1 = io.BytesIO(b'the content 1')
    storage.write(["Hello"], content1, size=len(content1.getvalue()))
    storage.clear_model()

    assert storage.open_read(["Hello"]).read() == content1.getvalue()


@pytest.mark.parametrize('test_content', [b'', b'test content'])
def test_write_to_root(init_storage_test, test_content):
    """Test simple upload to root folder."""
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    file_obj = ControlFileWrapper(orig_obj=io.BytesIO(test_content),
                                  task=MagicMock(cancelled=False))
    file_path = ['ThisIsATestFile.txt']

    v_id = storage.write(path=file_path, file_obj=file_obj, original_version_id=None,
                         size=len(test_content))
    assert v_id

    # wait for events
    assert wait_for_events(event_sink=event_sink, storage_create=1)
    logger.info('file creation passed.')

    # checking shallow copy immunity of event props
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)

    if init_storage_test.normalized_paths:
        tree_path = casefold_path(file_path)
    else:
        tree_path = file_path

    # check model
    node_props = storage.get_tree().get_node(tree_path).props
    assert v_id == node_props[VERSION_ID]

    # check event
    event_props = dict(is_dir=node_props[IS_DIR],
                       modified_date=mock.ANY,
                       size=mock.ANY,
                       version_id=node_props[VERSION_ID], shared=mock.ANY)

    assert any_args(call_arg_list=event_sink.storage_create.call_args_list,
                    storage_id=storage.storage_id,
                    path=file_path,
                    event_props=event_props), 'wrong event for path {}'.format(file_path)


# noinspection PyShadowingNames
def test_write_bigfile_cancel(init_storage_test):
    """Write to the root folder and then cancels it during transfer.

    Afterwards it is checked if the file exists. (It should not)
    """
    storage = init_storage_test.storage

    task = MagicMock(cancelled=False)

    # create a 400 MByte file buffer
    obj_size = 1024 * 1024 * 400
    logger.info('creating object with size %s', obj_size)
    file_obj = ControlFileWrapper(orig_obj=io.BytesIO(b'0' * obj_size),
                                  task=task)
    file_path = ['BiGfILE.dat']

    logger.info('uploading object with size %s', obj_size)
    copy_thread = threading.Thread(target=storage.write,
                                   kwargs=dict(path=file_path, file_obj=file_obj,
                                               original_version_id=None, size=obj_size))

    copy_thread.start()
    starttime = time.time()
    while file_obj.read_count <= 4 * 1024 * 1024 and time.time() < starttime + 10:
        time.sleep(0.01)
    task.cancelled = True
    logger.debug('Took %s seconds to write %s MByte', time.time() - starttime,
                 file_obj.read_count / (1024 * 1024))
    time.sleep(1)

    # check model
    tree = storage.get_tree()

    with pytest.raises(KeyError):
        tree.get_node(file_path)


def test_create_existing_folder(init_storage_test):
    """Create existing folder."""
    storage = init_storage_test.storage

    # should raise no error
    storage.make_dir(path=['c'])


@pytest.mark.crud
def test_create_dir(init_storage_test_without_files):
    """Just create a 10 level deep directory structure"""

    init_storage_test_without_files.storage.make_dir(['a'] * 10)


# def test_long_filename(init_storage_test_without_files):
#     """
#     Create existing folder.
#     """
#
#     storage = init_storage_test_without_files.storage
#     storage.start_events()
#
#     path = ['long', 'paths', 'are', 'shitty', 'to', 'handle', 'on', 'some',
#             'systems', 'you', 'know', 'windows', 'for', 'example',
#             'can', 'handle', 'file', 'with', '255', 'chars', 'by',
#             'default', 'if', 'you', 'want', 'longer', 'filenames',
#             'you', 'need', 'to', 'prefix', 'everything'] * 3
#
#     assert len(''.join(path)) > 256
#     storage.make_dir(path)
#
#     tree = storage.get_tree()
#
#     props = tree.get_node(path).props
#
#
#     # check event
#     event_props = dict(is_dir=True,
#                        modified_date=mock.ANY,
#                        size=mock.ANY,
#                        version_id=props[VERSION_ID])
#
#     assert any_args(call_arg_list=storage.event_sink.storage_create.call_args_list,
#                     storage_id=storage.storage_id,
#                     path=path,
# event_props=event_props), 'wrong event for path {}'.format(path)

def test_modify(init_storage_test):
    """Test simple write into root folder."""
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink
    data = b'abcdef'

    file_obj = ControlFileWrapper(orig_obj=io.BytesIO(data),
                                  task=MagicMock(cancelled=False))
    file_path = ['a', 'b', TEST_FILE_NAME]

    # write to storage
    storage.write(path=file_path, file_obj=file_obj, original_version_id=None,
                  size=len(data))

    # wait for events
    wait_for_events(event_sink=event_sink, storage_modify=1)

    # checking immunity
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)

    # check event
    node_props = storage.get_tree().get_node(file_path).props
    event_props = dict(is_dir=node_props[IS_DIR],
                       modified_date=mock.ANY,
                       size=mock.ANY,
                       version_id=node_props[VERSION_ID], shared=mock.ANY)

    # assert any_args(call_arg_list=event_sink.storage_modify.call_args_list,
    #                storage_id=storage.storage_id,
    #                path=file_path,
    # event_props=event_props), 'wrong event for path {}'.format(file_path)

    # pylint: disable=redefined-variable-type
    if init_storage_test.normalized_paths:
        file_path = IgnoringNormalizationPath(file_path)

    expected_calls = [(AnyItem(['storage_modify', 'storage_create']),
                       (),
                       dict(storage_id=storage.storage_id,
                            path=file_path,
                            event_props=event_props))]
    assert_expected_calls_in_timeout(expected_calls, event_sink)


def test_file_deletion(init_storage_test):
    """Tests for deletion of file."""
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    file_path = ['a', 'b', TEST_FILE_NAME]
    file_props = storage.get_tree(cached=True).get_node(file_path).props

    # delete non existing file
    with pytest.raises(FileNotFoundError):
        path = ['no_existing.txt']
        logger.info('Calling delete on no existing path %s', path)
        storage.delete(path=path, original_version_id='v_id')

    # delete file with wrong version id
    with pytest.raises(VersionIdNotMatchingError):
        storage.delete(path=file_path, original_version_id='wrong version id')

    # delete file with original version id
    storage.delete(path=file_path, original_version_id=file_props[VERSION_ID])

    # check events
    assert wait_for_events(event_sink=event_sink, storage_delete=1, timeout=30)
    assert_args(call_args=event_sink.storage_delete.call_args,
                storage_id=storage.storage_id,
                path=file_path)

    # checking reference immunity
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)


def test_folder_deletion(init_storage_test):
    """Tests for deletion of file."""

    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    expected_delete_path = [['a']]
    # delete non existing folder
    with pytest.raises(FileNotFoundError):
        storage.delete(path=['T'], original_version_id=FOLDER_VERSION_ID)

    # delete folder with wrong version id
    with pytest.raises(VersionIdNotMatchingError):
        storage.delete(path=['a'], original_version_id='wrong version id')

    # delete file with original version id
    storage.delete(path=['a'], original_version_id=FOLDER_VERSION_ID)

    # check events
    wait_for_events(event_sink=event_sink,
                    storage_delete=len(expected_delete_path))

    expected_calls = []
    for path in expected_delete_path:
        expected_calls.append(('storage_delete', (), dict(path=path,
                                                          storage_id=storage.storage_id)))
        with pytest.raises(KeyError):
            storage.get_tree(cached=True).get_node(path=path)
    logger.info('expected_calls: %s', expected_calls)
    assert_expected_calls_in_timeout(expected_calls, event_sink)

    # checking reference immunity
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)


def test_read_file(init_storage_test):
    """Reads file from storage and checks content."""

    storage = init_storage_test.storage
    test_content = init_storage_test.test_content

    file_path = ['a', 'b', TEST_FILE_NAME]
    file_props = storage.get_tree(cached=True).get_node(file_path).props

    # read non existing file
    with pytest.raises(FileNotFoundError):
        storage.open_read(path=['no_existing.txt'],
                          expected_version_id='000abcdedeff')

    # read file with wrong version id
    with pytest.raises(VersionIdNotMatchingError):
        storage.open_read(path=file_path, expected_version_id='000abcdedeff')

    # get file stream
    file_obj = storage.open_read(path=file_path,
                                 expected_version_id=file_props[VERSION_ID])
    file_obj = ControlFileWrapper(
        orig_obj=file_obj, task=MagicMock(cancelled=False))
    file_content = file_obj.read()
    assert file_content == test_content

    # get file stream with no version id
    file_obj = storage.open_read(path=file_path)
    file_obj = ControlFileWrapper(
        orig_obj=file_obj, task=MagicMock(cancelled=False))
    file_content = file_obj.read()
    assert file_content == test_content


def test_move_to_existing(init_storage_test):
    """Test moving file to exsiting file (replace)."""
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    target = ['a', 'b', TEST_FILE_NAME]
    source = ['a', 'to_be_move.txt']

    TESTDATA = b'data'
    source_vid = storage.write(path=source, file_obj=io.BytesIO(TESTDATA),
                               original_version_id=None, size=len(TESTDATA))
    target_vid = storage.get_tree().get_node(target).props[VERSION_ID]
    wait_for_events(event_sink=event_sink, storage_create=1)
    assert_expected_calls_in_timeout([(AnyItem(['storage_create', 'storage_modify']),
                                       (),
                                       dict(path=source,
                                            event_props=mock.ANY,
                                            storage_id=storage.storage_id))], event_sink)

    reset_event_sink(event_sink=event_sink)

    # move with wrong version ids
    with pytest.raises(VersionIdNotMatchingError):
        storage.move(source=source, target=target,
                     expected_source_vid='no', expected_target_vid=target_vid)

    # we either get a filenotfounderror because the target folder does not exist or
    # a version missmatch error
    with pytest.raises((VersionIdNotMatchingError, FileNotFoundError)):
        storage.move(source=source, target=target,
                     expected_source_vid=source_vid, expected_target_vid='no')

    logger.info('Moving file from <%s> to <%s>', '/'.join(source), '/'.join(target))
    new_vid = storage.move(source=source, target=target,
                           expected_source_vid=source_vid, expected_target_vid=target_vid)
    logger.debug('New version_id: %s', new_vid)
    assert new_vid

    # pylint: disable=redefined-variable-type
    if init_storage_test.normalized_paths:
        target = IgnoringNormalizationPath(target)

    expected_calls = []
    event_props = dict(is_dir=False, size=mock.ANY,
                       version_id=new_vid, modified_date=mock.ANY, shared=mock.ANY)

    if storage.storage_name in ('onedrivebusiness', 'sharepoint'):
        # some microsoft products first move and then update the version_id.

        expected_calls.append(('storage_modify',
                               (),
                               {'path': target,
                                'event_props': copy.copy(event_props),
                                'storage_id': storage.storage_id}))

        event_props['version_id'] = source_vid

    # If we deal with a SP that is able to emit "move" events (e.g. GDrive, OneDrive) we
    # should see a 'storage_move'. If the SP does not emit them the expected events should
    # be either 'storage_create' and/or 'storage_modify' + 'storage_delete' (e.g. Dropbox).
    if init_storage_test.emits_move_events:
        logger.debug("Dealing with storage that emits 'MOVE' events.")

        if source[-1] != target[-1]:
            logger.debug(
                "Source and target filename are different. Expecting a RENAME+MOVE.")
            # this includes a rename as well
            # since all the storage, supporting move are currently using the tree adapter this
            # has a seperate move event for the rename and for the move itself

            # rename
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source,
                                    'target_path': source[:-1] + [target[-1]],
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))

            # move
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source[:-1] + [target[-1]],
                                    'target_path': target,
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))
        else:
            logger.debug("Source and target filename are equal. Expecting a simple MOVE.")
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source,
                                    'target_path': target,
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))
    else:
        expected_calls.append((AnyItem(['storage_modify', 'storage_create']),
                               (),
                               dict(path=target,
                                    event_props=event_props,
                                    storage_id=storage.storage_id)))
        expected_calls.append(('storage_delete', (), dict(path=source,
                                                          storage_id=storage.storage_id)))
    assert_expected_calls_in_timeout(expected_calls, event_sink)

    # checking reference immunity
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)


def test_move_file_to_folder(init_storage_test):
    """
    Test moving of file.
    """
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    source_path = ['a', 'b', TEST_FILE_NAME]
    target_path = ['e', TEST_FILE_NAME]
    source_v_id = storage.get_tree(cached=True).get_node(
        source_path).props[VERSION_ID]

    # move non existing file
    with pytest.raises(FileNotFoundError):
        storage.move(source=['n.s'], target=target_path)

    # move file with wrong version id
    with pytest.raises(VersionIdNotMatchingError):
        storage.move(source=source_path, target=target_path,
                     expected_source_vid='no')

    # move file
    new_v_id = storage.move(
        source=source_path, target=target_path, expected_source_vid=source_v_id)

    logger.debug('Original VID:%s', source_v_id)
    logger.debug('NEw      VID:%s', new_v_id)

    # wait for events
    expected_calls = []
    event_props = dict(is_dir=False, size=mock.ANY,
                       version_id=new_v_id, modified_date=mock.ANY, shared=mock.ANY)

    if storage.storage_name in ('onedrivebusiness', 'sharepoint'):
        # some microsoft products first move and then update the version_id.

        expected_calls.append(('storage_modify',
                               (),
                               {'path': target_path,
                                'event_props': copy.copy(event_props),
                                'storage_id': storage.storage_id}))

        event_props['version_id'] = source_v_id

    # If we deal with a SP that is able to emit "move" events (e.g. GDrive, OneDrive) we
    # should see a 'storage_move'. If the SP does not emit them the expected events should
    # be either 'storage_create' and/or 'storage_modify' + 'storage_delete' (e.g. Dropbox).
    if init_storage_test.emits_move_events:
        logger.debug("Dealing with storage that emits 'MOVE' events.")
        expected_calls.append(('storage_move', (), dict(target_path=target_path,
                                                        source_path=source_path,
                                                        event_props=event_props,
                                                        storage_id=storage.storage_id)))
    else:
        expected_calls.append(
            (AnyItem(['storage_create', 'storage_modify']),
             (),
             dict(path=target_path,
                  event_props=event_props,
                  storage_id=storage.storage_id)))

        expected_calls.append(('storage_delete', (), dict(path=source_path,
                                                          storage_id=storage.storage_id)))

    assert_expected_calls_in_timeout(expected_calls, event_sink)

    # check model
    with pytest.raises(KeyError):
        storage.get_tree().get_node(source_path)

    # check file
    assert storage.get_tree().get_node(
        target_path).props[VERSION_ID] == new_v_id
    # check dir
    assert storage.get_tree().get_node(
        target_path[:-1]).props[VERSION_ID] == IS_DIR


@pytest.mark.parametrize("target_path", [
    ['z', TEST_FILE_NAME],
    ['new_dir', TEST_FILE_NAME],
    ['z', 'x', 'renamed.txt'],
    ['file_in_root.txt']])
def test_file_move(init_storage_test, target_path):
    """
    Test moving of file.
    """
    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    source_path = ['a', 'b', TEST_FILE_NAME]
    source_v_id = storage.get_tree().get_node(source_path).props[VERSION_ID]

    # move file
    version_id = storage.move(source=source_path, target=target_path,
                              expected_source_vid=source_v_id)

    # wait for events
    wait_for_events(event_sink=event_sink, storage_delete=1, storage_create=1)
    expected_calls = []
    event_props = dict(is_dir=False,
                       size=mock.ANY,
                       version_id=version_id,
                       modified_date=mock.ANY, shared=mock.ANY)

    if storage.storage_name in ('onedrivebusiness', 'sharepoint'):
        # some microsoft products first move and then update the version_id.

        expected_calls.append(('storage_modify',
                               (),
                               {'path': target_path,
                                'event_props': copy.copy(event_props),
                                'storage_id': storage.storage_id}))

        event_props['version_id'] = source_v_id

    if init_storage_test.emits_move_events:
        if source_path[-1] != target_path[-1]:
            # this includes a rename as well
            # since all the storage, supporting move are currently using the tree adapter this
            # has a seperate move event for the rename and for the move itself

            # rename
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source_path,
                                    'target_path': source_path[:-1] + [target_path[-1]],
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))

            # move
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source_path[:-1] + [target_path[-1]],
                                    'target_path': target_path,
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))
        else:
            expected_calls.append(('storage_move',
                                   (),
                                   {'source_path': source_path,
                                    'target_path': target_path,
                                    'storage_id': storage.storage_id,
                                    'event_props': event_props}))
    else:
        expected_calls.append((AnyItem(['storage_create', 'storage_modify']),
                               (),
                               dict(path=target_path,
                                    event_props=event_props,
                                    storage_id=storage.storage_id)))
        expected_calls.append(('storage_delete', (), dict(path=source_path,
                                                          storage_id=storage.storage_id)))
    assert_expected_calls_in_timeout(expected_calls, event_sink)

    # check model
    with pytest.raises(KeyError):
        storage.get_tree().get_node(source_path)
    assert storage.get_tree().get_node(
        target_path).props[VERSION_ID] == version_id

    # checking event immunity
    check_storage_event_reference_immunity(
        event_sink=event_sink, storage=storage)


def test_move_folder_with_content(init_storage_test):
    """Test moving of file."""
    logger.debug('starting test')

    storage = init_storage_test.storage
    event_sink = init_storage_test.event_sink

    source_path = ['a', 'b']
    target_path = ['b']
    source_v_id = storage.get_tree().get_node(source_path).props[VERSION_ID]

    # move file
    item_id = storage.move(source=source_path, target=target_path,
                           expected_source_vid=source_v_id)
    assert item_id == IS_DIR

    # wait for events
    expected_calls = []
    event_props = dict(is_dir=True,
                       size=mock.ANY,
                       version_id=item_id,
                       modified_date=mock.ANY, shared=mock.ANY)

    if init_storage_test.emits_move_events:
        expected_calls.append(('storage_move',
                               (),
                               {'source_path': source_path,
                                'target_path': target_path,
                                'event_props': event_props,
                                'storage_id': storage.storage_id}))

    else:
        expected_calls.append(('storage_create', (), dict(path=target_path,
                                                          event_props=event_props,
                                                          storage_id=storage.storage_id)))
        expected_calls.append(('storage_delete', (), dict(path=source_path,
                                                          storage_id=storage.storage_id)))
    assert_expected_calls_in_timeout(expected_calls, event_sink)

    # check reality
    with pytest.raises(KeyError):
        storage.get_tree().get_node(source_path)
    with pytest.raises(KeyError):
        storage.get_tree().get_node(source_path + [TEST_FILE_NAME])
    assert storage.get_tree().get_node(
        target_path).props[VERSION_ID] == item_id
    assert storage.get_tree().get_node(
        target_path + [TEST_FILE_NAME]).props[VERSION_ID]


def test_get_tree(init_storage_test):
    """
    Tests get_tree method of storage.
    """
    storage = init_storage_test.storage

    tree = storage.get_tree()

    # making sure model is deep copy
    assert tree is not storage.get_internal_model

    metrics = tree.props[METRICS]
    assert metrics.free_space > 0
    assert metrics.total_space > 0
    assert not metrics.offline
    assert metrics.storage_id == storage.storage_id

    # test non existing path
    with pytest.raises(KeyError):
        tree.get_node(['z'])

    # test all entries
    assert len(tree) == 6
    for test_path in init_storage_test.test_paths:
        assert tree.get_node(test_path)

    # test sub tree
    sub_tree = tree.get_node(['a'])
    assert len(sub_tree) == 4
    assert sub_tree.get_node(['b'])
    assert sub_tree.get_node(['c'])
    assert sub_tree.get_node(['b', TEST_FILE_NAME])


# def test_jpeg_upload(init_storage_test_without_files_events):
#     """
#     Images are often handled different by csps, this should testwise upload a jpeg
#     """
#     if isinstance(init_storage_test_without_files_events.storage, EncryptingFileSystem):
#         pytest.skip('not executed')
#
#     delete_all_files(init_storage_test_without_files_events.storage,
#                      init_storage_test_without_files_events.event_sink)
#
#     jpeg_path = os.path.join(os.path.dirname(__file__), 'bird.jpg')
#
#     stream = open(jpeg_path, 'rb')
#
#     version_id = init_storage_test_without_files_events.storage.write(['bird.jpg'],
#                                                                       stream)
#
#     expected = [
#         ('storage_create',
#          (),
#          dict(path=['bird.jpg'],
#               event_props=dict(size=os.stat(jpeg_path).st_size,
#                                version_id=version_id,
#                                modified_date=mock.ANY,
#                                is_dir=False),
#               storage_id=init_storage_test_without_files_events.storage.storage_id))]
#
#     assert_expected_calls_in_timeout(expected,
#                                      init_storage_test_without_files_events.event_sink)


def test_get_tree_children(init_storage_test):
    """Tests get_tree method of storage."""
    logger.info('[test_get_tree_children] started')
    storage = init_storage_test.storage

    # test assert folders
    children = list(storage.get_tree_children(path=['a']))
    assert len(children) == 2
    assert any((name == 'b' for name, _ in children))
    assert any((name == 'c' for name, _ in children))

    # test non existing path
    with pytest.raises(FileNotFoundError):
        list(storage.get_tree_children(path=['z']))


def test_public_sharing_link_creation(init_storage_test):
    """
    Test creation of public sharing links
    """
    storage = init_storage_test.storage

    if isinstance(storage, GoogleDrive):
        # TODO: bad
        pytest.skip('Google drive is not testable atm. remove me ASAP')

    event_sink = init_storage_test.event_sink
    test_file = ['a', 'b', TEST_FILE_NAME]

    if not storage.supports_sharing_link:
        with pytest.raises(NotImplementedError):
            storage.create_public_sharing_link(test_file)
        return

    # non existing file
    with pytest.raises((StorageError, FileNotFoundError)):
        storage.create_public_sharing_link([TEST_FILE_NAME])

    # root
    with pytest.raises(StorageError):
        storage.create_public_sharing_link([])

    # file
    logger.info('>>> Create public sharing link for file %s', test_file)
    assert storage.create_public_sharing_link(test_file)
    assert storage.get_tree(cached=False).get_node(test_file).props[SHARED]

    props = storage.get_tree().get_node(test_file).props
    assert props[SHARED]
    assert storage.get_tree(cached=True).get_node(test_file).props[SHARED]

    event_props = dict(is_dir=False,
                       size=mock.ANY,
                       version_id=props[VERSION_ID],
                       modified_date=mock.ANY,
                       shared=True,
                       share_id=mock.ANY,
                       public_share=True)
    expected_calls = [('storage_modify', (), dict(path=test_file,
                                                  event_props=event_props,
                                                  storage_id=storage.storage_id))]
    assert_expected_calls_in_timeout(expected_calls, event_sink)

    reset_event_sink(event_sink=event_sink)

    # folder
    logger.info('>>> Create public sharing link for folder %s', test_file[:-1])
    assert storage.create_public_sharing_link(test_file[:-1])
    assert storage.get_tree(cached=True).get_node(test_file).props[SHARED]
    props = storage.get_tree().get_node(test_file[:-1]).props
    assert props[SHARED]
    event_props = dict(is_dir=True,
                       size=mock.ANY,
                       version_id=props[VERSION_ID],
                       modified_date=mock.ANY,
                       shared=True,
                       share_id=mock.ANY,
                       public_share=True)
    expected_calls = [('storage_modify', (), dict(path=test_file[:-1],
                                                  event_props=event_props,
                                                  storage_id=storage.storage_id))]
    assert_expected_calls_in_timeout(expected_calls, event_sink)


def test_create_open_in_web_link(init_storage_test):
    """Test creation of public sharing links."""
    storage = init_storage_test.storage
    test_file = ['a', 'b', TEST_FILE_NAME]

    if not storage.supports_open_in_web_link:
        with pytest.raises(NotImplementedError):
            storage.create_open_in_web_link(test_file)
        return
    # root should a return a link
    assert storage.create_open_in_web_link([])
    # None path
    with pytest.raises((jars.StorageError)):
        storage.create_open_in_web_link(None)
    # Invalid argument
    with pytest.raises((jars.StorageError)):
        storage.create_open_in_web_link('test')

    # file
    assert storage.create_open_in_web_link(test_file)

    # folder
    assert storage.create_open_in_web_link(test_file[:-1])


def test_make_dir(init_storage_test):
    """
    Tests that the make dir function always returns a version id
    :param init_storage_test:
    :return:
    """
    storage = init_storage_test.storage

    existing_folder = ['a']
    new_folder = ['qwertz']
    assert storage.make_dir(existing_folder) is not None
    assert storage.make_dir(new_folder) is not None
    # TODO: REENABLE THIS
    # existing_file = ['a', 'b', 'test  äää  111 üüü.txt']
    # with pytest.raises(InvalidOperationError):
    #     assert storage.make_dir(existing_file) is not None


@pytest.mark.manual
@pytest.mark.parametrize("public_share", [
    False,
    True
])
def test_shared_properties_and_link(init_storage_test, public_share):
    r"""Test if the properties are properly sent via storage_modify

    And that the properties are then persistently available via the tree.

    1.) Let the user share the directory "a" to another user.
        1a.) check the storage emits the event (storage_id and shared)
        1b.) check if get_tree(cache=False) also contains that (storage_id and shared)
        1c.) check if it is listed via get_shared_folders
    2.) Let the user un-share the folder "a"
        2a.) check the storage emits the removed properties
        2b.) check if the storage has removed the properties from the try:
        2c.) check if the share has been removed from get_shared_folders

    Sample invocation:
    To run the thest tests for OneDrive

    `pytest -s -vv tests/storage/test_storage.py::test_shared_properties_and_link \
    -k onedrive --manual`
    """
    webbrowser.open(init_storage_test.storage.create_open_in_web_link(['a']))
    if public_share:
        input(termcolor.colored('Please share folder "a" with a public link [ENTER]', 'green',
                                attrs=['blink', 'bold']))
    else:
        input(termcolor.colored('Please share folder "a" to another random user and hit [ENTER]',
                                'green', attrs=['blink', 'bold']))

    expected_event_props = {IS_DIR: True,
                            'size': mock.ANY,
                            VERSION_ID: IS_DIR,
                            'modified_date': mock.ANY,
                            'shared': True,
                            'share_id': mock.ANY,
                            'public_share': public_share}

    expected_calls = [('storage_modify',
                       (),
                       {'path': ['a'],
                        'event_props': expected_event_props,
                        'storage_id': init_storage_test.storage.storage_id})]

    # check 1a.
    assert_expected_calls_in_timeout(expected_calls, init_storage_test.event_sink)

    # check 1b.
    # try to get the share id by the tree
    assert 'share_id' in init_storage_test.storage.get_tree(cached=True).get_node(['a']).props
    node_a = init_storage_test.storage.get_tree(cached=False).get_node(['a'])
    assert 'share_id' in node_a.props
    share_id = node_a.props['share_id']

    # now check if all subfolders are either have the same share id or none set
    for node in node_a:
        if 'share_id' in node.props:
            assert node.props['share_id'] == share_id

    # public_share should be false in storage node props for cached and uncached.
    node = init_storage_test.storage.get_tree(cached=True).get_node(['a'])
    assert node.props['public_share'] == public_share

    node = init_storage_test.storage.get_tree(cached=False).get_node(['a'])
    assert node.props['public_share'] == public_share

    # check 1c.
    shared_folders = init_storage_test.storage.get_shared_folders()
    assert [item for item in shared_folders if list(item.path) == ['a']]

    init_storage_test.event_sink.reset_mock()

    # now we test removing the share
    webbrowser.open(init_storage_test.storage.create_open_in_web_link(['a']))
    input('Please UNshare folder "a" to and hit [ENTER]')

    # DELETE for share props
    expected_event_props = {IS_DIR: True,
                            'size': mock.ANY,
                            VERSION_ID: IS_DIR,
                            'modified_date': mock.ANY,
                            'shared': False,
                            'share_id': bushn.DELETE,
                            'public_share': bushn.DELETE}

    expected_calls = [('storage_modify',
                       (),
                       {'path': ['a'],
                        'event_props': expected_event_props,
                        'storage_id': init_storage_test.storage.storage_id})]
    # check 2a.
    assert_expected_calls_in_timeout(expected_calls, init_storage_test.event_sink)

    # share_id and public_share should have been deleted from node props for cached and uncached.
    node = init_storage_test.storage.get_tree(cached=True).get_node(['a'])
    assert 'public_share' not in node.props or node.props['public_share'] == bushn.DELETE
    assert 'share_id' not in node.props or node.props['share_id'] == bushn.DELETE

    node = init_storage_test.storage.get_tree(cached=False).get_node(['a'])
    assert 'public_share' not in node.props or node.props['public_share'] == bushn.DELETE
    assert 'share_id' not in node.props or node.props['share_id'] == bushn.DELETE
    # no shared fodlers should exist
    # check 2c.
    assert list(init_storage_test.storage.get_shared_folders()) == []

    init_storage_test.event_sink.reset_mock()


# pylint: disable=protected-access
# pylint: disable=too-many-statements
def test_selective_sync(init_storage_test):
    """Test selective sync."""
    storage = init_storage_test.storage

    if isinstance(storage, Filesystem):
        pytest.skip('Not on Filsystem.')

    init_storage_test.storage._event_sink = FilterEventSinkWrapper(
        init_storage_test.storage._event_sink, init_storage_test.storage.filter_tree)

    if hasattr(storage, 'event_sink'):
        init_storage_test.storage.event_sink = init_storage_test.storage._event_sink

    # set the filter to ['a', 'c']
    storage.filter_tree.add_child('a').add_child('c')

    logger.info('>> Restart events/simulating a restart')
    init_storage_test.storage.stop_events(join=True)
    init_storage_test.storage.update()
    init_storage_test.storage.start_events()

    expected_calls = []
    # Add a directory and a file inside it
    # An event for should be emitted for both.
    logger.info('>> Add directory /xxx. -> storage_create.')
    storage.make_dir(['xxx'])
    expected_calls.append(('storage_create', (), dict(path=['xxx'],
                                                      event_props=mock.ANY,
                                                      storage_id=storage.storage_id)))

    logger.info('>> Add file /xxx/hello123. -> storage_create.')
    storage.write(['xxx', 'hello123'], io.BytesIO(b'lala'), size=4)
    expected_calls.append(('storage_create', (), dict(path=['xxx', 'hello123'],
                                                      event_props=mock.ANY,
                                                      storage_id=storage.storage_id)))

    logger.info('>> Add directory /c/d -> hidden by filter')
    storage.write(['c', 'd'], io.BytesIO(b'lala'), size=4)
    # time.sleep(0.5)

    logger.info('>> Add file /a/hello123. -> storage_create')
    storage.write(['a', 'hello123'], io.BytesIO(b'lala'), size=4)
    expected_calls.append(('storage_create', (), dict(path=['a', 'hello123'],
                                                      event_props=mock.ANY,
                                                      storage_id=storage.storage_id)))

    assert_expected_calls_in_timeout(expected_calls, init_storage_test.event_sink,
                                     timeout=30)

    # small comment to help
    # [['a'], ['a', 'b'], ['a', 'c'], ['a', 'b', TEST_FILE_NAME], ['c']]
    # c and a,c are dirs

    with pytest.raises(KeyError):
        logger.info('>> /a/b/%s should not be in the cached tree.', TEST_FILE_NAME)
        storage.get_tree(cached=True).get_node(['a', 'b', TEST_FILE_NAME])

    with pytest.raises(KeyError):
        logger.info('>> /a/b/ should not be in the cached tree.')
        storage.get_tree(cached=True).get_node(['a', 'b'])

    with pytest.raises(KeyError):
        logger.info('>> /c should not be in the cached tree.')
        storage.get_tree(cached=True).get_node(['c'])

        # assert check that ['c', 'd'] is not a called event (file created in an ignored
        # subdir)
        # assert (mock.call(path=['xxx'], storage_id=storage.storage_id,
        #                   event_props=mock.ANY) not in
        #         init_storage_test.event_sink.storage_create.calls)

    calls = init_storage_test.event_sink.storage_create.calls
    logger.info('>> Calls made: %s', len(calls))
    for call in calls:
        logger.info('>>     %s', call)

    # check that get_tree_children is not filtered
    logger.info('>> Check that tree is not filtered.')
    assert set([name for name, _ in storage.get_tree_children([])]) == {'a', 'c', 'xxx'}

    # check if the filter tree contains ['xxx']
    logger.info('>> Check that /xxx is in the filter_tree')
    assert storage.filter_tree.has_child('xxx')
    logger.info('>> Check that /c is not in the filter_tree')
    assert not storage.filter_tree.has_child('c')

    # check the tree of the storage
    logger.info('>> Check that the cached tree has /xxx/hello123')
    assert storage.get_tree(cached=True).get_node(['xxx', 'hello123'])
    logger.info('>> Check that the cached does not have /c')
    assert not storage.get_tree(cached=True).has_child('c')

    logger.info('>> Check the model has not been overwritten by filter tree.')
    # assert the model has not been overwritten by the filter tree
    # This fails when you use get_tree to set the model inside update.
    storage.clear_model()
    storage.update()
    internal_model = storage.get_internal_model()
    assert internal_model.has_child('c')
# pylint: enable=protected-access
# pylint: enable=too-many-statements


@pytest.mark.parametrize("test_size", [1024 * 1024 * 10])
def test_huge_upload(init_storage_test_without_files, test_size, tmpdir):
    """ upload and downloads huger files """
    storage = init_storage_test_without_files.storage
    # event_sink = init_storage_test_without_files.event_sink

    path = [str(test_size) + '.txt']

    random_file = tmpdir.join("hello.dat")
    random_file.write_binary(os.urandom(test_size), ensure=True)

    copy_thread = threading.Thread(target=storage.write,
                                   kwargs=dict(path=path, file_obj=random_file.open('rb'),
                                               size=test_size))

    copy_thread.start()
    start_time = time.time()
    while copy_thread.is_alive():
        logger.debug("upload is in progress...")
        time.sleep(1)

    if time.time() - start_time == 0:
        try:
            logger.debug("done uploading speed was %f KiB/s",
                         ((test_size / 1024) / (time.time() - start_time)))
        except ZeroDivisionError:
            logger.debug("done uploading speed was infinitely fast")

    f_in = storage.open_read(path)
    f_golden = random_file.open('rb')

    total_read = 0

    compare_block_size = 1024 * 1024
    while True:
        buf = f_in.read(compare_block_size)
        total_read += len(buf)
        buf_golden = f_golden.read(len(buf))

        logger.debug('comparing %d bytes now', total_read)
        if not isinstance(buf, bytes):
            # some storages return different sequences, its fine
            buf = bytes(buf)

        assert buf == buf_golden

        if not buf:
            break
    assert total_read == test_size


def check_storage_event_reference_immunity(event_sink, storage):
    """
    tests for if the storages are not emitting shallow copies of node properties
    This is crucial as such events could be modified during enqueued for the sync engine
    leading to inconsistent behaviour while the syncegine and other components process
    it. Rule: All emitted non-immutable s must be deep-copies!!
    :param event_sink: the event sink containing the event from the storage
    :param storage: the storage under test
    """
    # checking input
    assert event_sink
    assert storage

    # any file system storage is ignored as no internal model
    if isinstance(storage, Filesystem):
        return

    # getting internal model
    model = storage.get_internal_model()
    assert model

    # checking all events in sink
    for call_event in event_sink.method_calls:

        # getting event the sink was called with
        (name, _, kwargs) = call_event

        # cannot check anything for delete events as node not present
        if name == 'storage_delete':
            continue

        # getting path
        path = None
        if name == 'storage_move':
            path = kwargs['target_path']
        else:
            path = kwargs['path']
        assert path

        # getting relevant node (if required case insensitive)
        # if node cannot be obtained by service -> continuing (other problem but
        # no reference error)
        relevant_node = None
        try:
            relevant_node = model.get_node(path=path)
        except KeyError:
            try:
                relevant_node = model.get_node(path=casefold_path(path))
            except KeyError:
                continue
        assert relevant_node

        # checking path
        assert relevant_node.path is not path

        # checking event props if present
        event_props = kwargs['event_props']
        assert relevant_node.props is not event_props


def test_delete_event_order(init_storage_test):
    """Test if there is a single delete event if you delete a full subtree."""
    provider = init_storage_test.storage
    if not isinstance(provider, Filesystem):
        pytest.skip("Only necessary for filesystem tests")
    logger.info("Deleting the folder")
    provider.delete(path=['a'],
                    original_version_id=None)

    expected_calls = [('storage_delete', (), dict(path=['a'], storage_id='filesystem'))]
    assert_expected_calls_in_timeout(expected_calls, init_storage_test.event_sink,
                                     timeout=10)


def test_internal_model_copied(init_storage_test):
    """Test if get_tree returns a copy of the internal model."""
    provider = init_storage_test.storage
    external_tree = provider.get_tree(cached=True)
    internal_model = provider.get_internal_model()

    if internal_model is None:
        pytest.skip("This storage does not implement `get_internal_model`!")
    external_tree.get_node(['a']).name = 'asdf'
    with pytest.raises(KeyError):
        internal_model.get_node(['asdf'])


def test_update_triggers_no_events(init_storage_test_without_files_events):
    """Test if storage.update() does not trigger events."""
    event_sink = init_storage_test_without_files_events.event_sink
    storage = init_storage_test_without_files_events.storage

    if storage.storage_id == 'googledrive':
        pytest.skip("GoogleDrive does not support this test!")

    delete_all_files(storage=storage, event_sink=event_sink, reset=True)

    # Create another file
    storage.write(
            path=['events'], file_obj=io.BytesIO(b'ladida'),
            original_version_id=None, size=len(b'ladida'))

    # Verify that the proper event has been triggered
    event_props = dict(is_dir=False,
                       modified_date=mock.ANY,
                       size=mock.ANY,
                       version_id=mock.ANY, shared=mock.ANY)

    expected_calls = [('storage_create', (),
                      dict(path=['events'],
                           storage_id=storage.storage_id,
                           event_props=event_props))]
    assert_expected_calls_in_timeout(expected_calls, event_sink, timeout=10)

    # Stop the poller
    storage.stop_events(join=True)

    delete_all_files(storage=storage, event_sink=event_sink, reset=True)

    # Create a file on the storage
    storage.write(
            path=['a', 'b', 'events'], file_obj=io.BytesIO(b'ladida'),
            original_version_id=None, size=len(b'ladida'))

    # Run update()
    storage.update()

    # No events should have been triggered
    assert event_sink.mock_calls == []


# --------------------------------
# ------- HELPER METHODS ---------
# --------------------------------


def mock_event_sink():
    """
    Mocks events sink with given methods.
    :return mocked event sync.
    """

    mock = MagicMock(spec=['storage_delete', 'storage_create', 'storage_modify',
                           'storage_move', 'storage_offline', 'storage_online'])
    return mock


def wait_for_events(event_sink, timeout=40, reset=False, **kwargs):
    """Wait a specific time for a specific amount of events from storage.

    :param event_sink: from which event is expected.
    :param timeout: max wait time in secons.
    :param reset: true if event count should be reset afterwards
    :param kwargs: key is method name and value is number of calls for success
    """
    def call_count_match(**kwargs):
        """Check event calls."""
        for method_name, expected_count in kwargs.items():
            method = getattr(event_sink, method_name)
            if method.call_count < expected_count:
                return False
        return True

    wait_sec_count = 0

    max_time = int(time.time()) + timeout
    while int(time.time()) < max_time and not call_count_match(**kwargs):

        # print output every second
        waited_secs = int(max_time - time.time())
        if waited_secs != wait_sec_count:
            logger.info('waiting... %d for method count: %s event_sink.storage_create: %s'
                        ' event_sink.storage_delete: %s event_sink.storage_modify: %s'
                        ' event_sink.storage_move: %s',
                        int(max_time - time.time()),
                        kwargs,
                        event_sink.storage_create.call_count,
                        event_sink.storage_delete.call_count,
                        event_sink.storage_modify.call_count,
                        event_sink.storage_move.call_count)
            wait_sec_count = waited_secs

        time.sleep(0.01)

    # has to be done before resetting
    match = call_count_match(**kwargs)

    if reset:
        reset_event_sink(event_sink=event_sink)

    return match


def reset_event_sink(event_sink):
    """
    Resets all mocks for event sink methods.
    """
    event_sink.reset_mock()


# noinspection PyBroadException
# pylint: disable=broad-except
def delete_all_files(storage, event_sink, reset=False, timeout=30):
    """Deletes all files and waits for delete events."""

    reset_event_sink(event_sink=event_sink)

    logger.info("Deleting all files... (timeout: %s)", timeout)

    start_time = time.time()
    try:
        while time.time() < start_time + timeout:
            storage.update()
            delete_count = 0
            file_tree = storage.get_tree()
            expected_calls = []

            # stop if tree is empty
            if len(file_tree) == 1:
                break

            for file in file_tree.children:
                logger.info('deleting %s', file.path)
                storage.delete(path=file.path,
                               original_version_id=file.props['version_id'])
                expected_calls.append(('storage_delete', (),
                                       dict(path=file.path,
                                            storage_id=storage.storage_id)))
                delete_count += 1

        wait_for_events(event_sink=event_sink, storage_delete=delete_count)

        assert len(storage.get_tree()) == 1

    except Exception:
        logger.exception('error while deleting all files')

    if reset:
        reset_event_sink(event_sink=event_sink)

    logger.info("[delete_all_files] done")


def assert_expected_calls_in_timeout(expected_calls, mock, poll_interval=0.1, timeout=20):
    """Check if the expected_calls are called on the mock in within the timeout."""
    logger.info('expecting %d calls in %d s', len(expected_calls), timeout)
    max_time = int(time.time()) + timeout
    actual_matched_calls = []
    wait_sec_count = 0
    while True:
        for call in mock.method_calls:
            with contextlib.suppress(ValueError):
                # suppress ValueErrors for now. The result will be provided later.
                index = expected_calls.index(call)
                actual_matched_calls.append(expected_calls.pop(index))

        # check timeout with assert
        assert int(time.time()) < max_time, \
            "timeout of {}s reached" \
            "\n ***called: ***\n {} " \
            "\n ***matched:***\n {} " \
            "\n ***missing:***\n {}".format(
                timeout,
                pprint.pformat([tuple(call) for call in mock.method_calls]),
                pprint.pformat(actual_matched_calls),
                pprint.pformat(expected_calls))
        if not expected_calls:
            break

        time.sleep(poll_interval)

        waited_secs = int(max_time - time.time())
        if waited_secs != wait_sec_count:
            logger.debug('waiting... %d', waited_secs)
            wait_sec_count = waited_secs

    assert not expected_calls, \
        "not everything was called.\n called: {}\n matched: {} ".format(
            mock.method_calls, actual_matched_calls)


def assert_expected_calls_not_in_timeout(expected_calls, mock, poll_interval=0.1, timeout=20):
    """Check that the methods given by expected calls are not called on the mock."""
    logger.debug('CHECKING CALLS')
    max_time = int(time.time()) + timeout
    actual_matched_calls = []
    wait_sec_count = 0
    while True:
        for call in mock.method_calls:
            with contextlib.suppress(ValueError):
                # we supress that, we will see the result later anyways
                index = expected_calls.index(call)
                actual_matched_calls.append(expected_calls.pop(index))

        # check timeout with assert
        if int(time.time()) > max_time or not expected_calls:
            break

        time.sleep(poll_interval)

        waited_secs = int(max_time - time.time())
        if waited_secs != wait_sec_count:
            logger.debug('waiting... %d', waited_secs)
            wait_sec_count = waited_secs

    assert expected_calls, \
        "Some methods were called." \
        "\n ***called: ***\n {} " \
        "\n ***matched:***\n {} " \
        "\n ***missing:***\n {}".format(
            pprint.pformat([tuple(call) for call in mock.method_calls]),
            pprint.pformat(actual_matched_calls),
            pprint.pformat(expected_calls))

if __name__ == '__main__':
    storages = {'gdrive': GoogleDrive,
                'dropbox': jars.dropbox.Dropbox,
                'onedrive': jars.microsoft.OneDrive,
                'onedrive_business': jars.microsoft.OneDriveBusiness,
                'office365': jars.microsoft.Office365Groups
                }
    if len(sys.argv) < 2:
        print('Usage: python tests/test_storage.py storage_name\n'
              '\n  example: python tests/test_storage.py gdrive'
              '\n  avaliable storages: %s' % ', '.join(storages.keys()))

    obtain_token(storages[sys.argv[1]])


class IgnoringNormalizationPath():
    """Wraps path and compares normalized path components."""

    def __init__(self, path):
        self.plain_path = path
        self.normalized_path = casefold_path(path)

    def __eq__(self, other):
        """Test for equality of casefolded paths."""
        if not isinstance(other, list):
            return False

        return self.normalized_path == casefold_path(other) or other == self.plain_path


class AnyItem():
    """Wrap equal method to check item is in list."""

    def __init__(self, valid_items):
        self._valid_items = valid_items

    def __eq__(self, other):
        """Overwrite __eq__ to get the desired behaviour."""
        return other in self._valid_items

    def __repr__(self):
        """Return readable oneliner."""
        return 'AnyItem ' + ' or '.join(self._valid_items)
