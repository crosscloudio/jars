"""Configuration for pytest.
"""
import io
# pylint: disable=redefined-outer-name,invalid-name
import logging
from collections import namedtuple
from functools import partial
from unittest import mock

import pytest
import bushn

from jars import IS_DIR, METRICS, VERSION_ID
from jars.fs import Filesystem

from tests.test_sharepoint import init_sharepoint
from tests.test_nextcloud import init_nextcloud
from tests.test_owncloud import init_owncloud

from .test_storage import (TEST_FILE_NAME, IgnoringNormalizationPath,
                           assert_expected_calls_in_timeout, delete_all_files,
                           init_dropbox, init_filesystem,
                           init_googledrive, init_office365_groups,
                           init_onedrive, init_onedrive_business,
                           init_cifs, reset_event_sink, wait_for_events)

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add an option to run manual tests."""
    parser.addoption("--manual", action="store_true",
                     help="run semi automatic tests, which require manual interaction.")


def pytest_runtest_setup(item):
    """Decide which tests to skip based on wether the --manual flag is set."""
    man_mark = item.get_marker("manual")
    man_opt = item.config.getoption("--manual")

    if man_mark is None and man_opt:
        # @pytest.manual.mark is not set, but --manual is
        pytest.skip("skipping non manual test because --manual is set")
    elif man_mark is not None and not man_opt:
        # @pytest.manual.mark is set but --manual is not set
        pytest.skip("skipping manual test use --manual to run")


STORAGES = [init_nextcloud,
            init_owncloud,
            init_dropbox,
            init_filesystem,
            init_onedrive,
            init_googledrive,
            init_onedrive_business,
            init_office365_groups,
            init_sharepoint,
            init_cifs]

# Trim the init_ from the function names
STORAGE_IDS = [storage.__name__[5:] for storage in STORAGES]

# pylint: disable=too-many-locals


@pytest.fixture(params=STORAGES,
                ids=STORAGE_IDS)
def init_storage_test_without_files(request):
    """Initialises storage without test files."""
    init_storage = request.param()
    storage = init_storage.storage

    # check if test should be executed
    if not init_storage.is_executed:
        pytest.skip('not executed on storage')

    if init_storage.finalizer is not None:
        request.addfinalizer(init_storage.finalizer)

    logger.info(
        '*************** INITIALIZING TEST for %s ********************', storage)

    assert storage.auth

    return init_storage


@pytest.fixture
def init_storage_test_without_files_events(init_storage_test_without_files, request):
    """Fixture for a storage with events enabled."""
    # start event processing
    init_storage_test_without_files.storage.start_events()
    # stop events after the test
    request.addfinalizer(
        partial(init_storage_test_without_files.storage.stop_events, join=True))

    return init_storage_test_without_files


@pytest.fixture
def init_storage_test(init_storage_test_without_files_events):
    """Inits the storage tests with a bunch of files."""
    storage = init_storage_test_without_files_events.storage
    event_sink = init_storage_test_without_files_events.event_sink

    # this ensures no files and dirs are existing except the root node
    delete_all_files(storage=storage, event_sink=event_sink, reset=True)

    # check if the cached tree is empty as well
    tree = storage.get_tree(cached=True)
    assert len(tree) == 1, 'tree is not empty\n' + bushn.tree_to_str(tree)

    # free_space_before = tree.props[METRICS].free_space
    total_space_before = tree.props[METRICS].total_space

    # create test file structure
    test_paths = [['a'], ['a', 'b'], ['a', 'c'],
                  ['a', 'b', TEST_FILE_NAME], ['c']]
    test_content = b'test content'
    assert storage.write(
        path=['a', 'b', TEST_FILE_NAME], file_obj=io.BytesIO(test_content),
        original_version_id=None, size=len(test_content))

    storage.make_dir(path=['a', 'c'])
    storage.make_dir(path=['c'])

    # wait for events
    logger.info('waiting for %s storage_create in init_storage_test', len(test_paths))
    wait_for_events(event_sink=event_sink, storage_create=len(test_paths))

    # get tree
    tree = storage.get_tree(cached=False)

    assert not tree.get_node(['a', 'b', TEST_FILE_NAME]).props[IS_DIR]

    # check event arguments and model
    expected_calls = list()
    for path in test_paths:
        # logger.info('### tree: %s', bushn.tree_to_str(tree))
        # check model
        node = tree.get_node(path)

        # check event
        logger.debug('node name:%s props:%s', node.name, node.props)
        event_props = dict(is_dir=node.props[IS_DIR],
                           size=mock.ANY,
                           version_id=node.props[VERSION_ID],
                           modified_date=mock.ANY, shared=mock.ANY)

        if init_storage_test_without_files_events.normalized_paths:
            path = IgnoringNormalizationPath(path)

        expected_calls.append(('storage_create', (), dict(path=path,
                                                          event_props=event_props,
                                                          storage_id=storage.storage_id)))

    assert_expected_calls_in_timeout(expected_calls, event_sink)

    tree = storage.get_tree()
    # free_space_after = tree.props[METRICS].free_space
    total_space_after = tree.props[METRICS].total_space

    # on some storages including fs this change is not enough
    if not isinstance(storage, Filesystem):
        assert total_space_before <= total_space_after

    # check model entries for folder and files
    assert tree.get_node(['a']).props[IS_DIR]
    assert tree.get_node(['a', 'b']).props[IS_DIR]
    assert tree.get_node(['a', 'c']).props[IS_DIR]
    assert tree.get_node(['c']).props[IS_DIR]
    assert not tree.get_node(['a', 'b', TEST_FILE_NAME]).props[IS_DIR]

    reset_event_sink(event_sink=event_sink)

    logger.info(
        '*************** INITIALIZED TEST for %s ***********************', str(storage))

    return_type = namedtuple('InitStorageTest', ['storage', 'event_sink', 'test_content',
                                                 'test_paths', 'emits_move_events',
                                                 'normalized_paths'])
    return return_type(
        storage=storage, event_sink=event_sink, test_content=test_content,
        test_paths=test_paths,
        emits_move_events=init_storage_test_without_files_events.emits_move_events,
        normalized_paths=init_storage_test_without_files_events.normalized_paths)


@pytest.fixture(scope="module")
def office365_fixture():
    """Wrap init_office365_groups in fixture to reduce number of setup/teardowns."""
    return init_office365_groups()
