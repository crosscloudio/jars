"""This modules tests the jars.fs.macos.__init__.py."""
import logging
# pylint: disable=redefined-outer-name
# pylint: disable=unused-variable
import sys
import time

import mock
import bushn
import pytest

from jars.fs import Filesystem
from jars import FILESYSTEM_ID
import os

if sys.platform == 'darwin':
    from jars.fs import macos

logger = logging.getLogger(__name__)

# These tests should only be run on MacOS/darwin platform
pytestmark = pytest.mark.skipif(sys.platform != 'darwin', reason="Only for MacOS")


@pytest.fixture
def base_tree():
    """Simple tree with 4 nodes.

    a
    +-b
    +-a
    c
    """
    tree = bushn.Node(None)
    a_node = tree.add_child('a', props={'_inode': 'a_node'})
    c_node = tree.add_child('c', props={'_inode': 'c_node'})

    a_node.add_child('b', props={'_inode': 'b_node'})
    a_node.add_child('a', props={'_inode': 'aa_node'})

    logger.info('base_tree fixture\n%s', bushn.tree_to_str(tree, prop_key='_inode'))
    return tree


# def test_is_new(base_tree):
#     """Test a is_new function created by build_detectors"""
#     _, _, is_new = macos.build_detectors(base_tree)
#     assert is_new('new', {'_inode': 'new_node'})
#     assert not is_new(name='a', props={'_inode': 'a_node'})
#
#
# def test_is_new_in_sub_tree(base_tree):
#     """Test a is_new function created by build_detectors with a_node as a parent"""
#     _, _, is_new = macos.build_detectors(base_tree.get_node(['a']))
#
#     assert is_new('new', {'_inode': 'new_node'})
#     # TODO: make this work as well.
#     # assert is_new(name='a', props={'_inode': 'a_node'})
#     assert not is_new(name='a', props={'_inode': 'aa_node'})
#
#
# def test_renamed(base_tree):
#     """Test is_renamed created by build_detectors"""
#     is_renamed, _, _ = macos.build_detectors(base_tree)
#
#     # is rename is only true if the inode matches
#     assert is_renamed(name='renamed_a', props={'_inode': 'a_node'})
#     assert not is_renamed(name='renamed_a', props={'_inode': 'other_node'})
#
#
# def test_not_renamed(base_tree):
#     """ Test is renamed created by build detectors does not detect not renamed items"""
#     is_renamed, _, _ = macos.build_detectors(base_tree)
#     assert not is_renamed(name='a', props={'_inode': 'a_node'})
#
#
# def test_renamed_from(base_tree):
#     """Test renamed_from created by build_detectors"""
#     _, renamed_from, _ = macos.build_detectors(base_tree)
#     node_a = base_tree.get_node(['a'])
#     assert renamed_from(name='renamed_a', props={'_inode': 'a_node'}) == node_a


# def test_renamed_in_sub_tree(base_tree):
#     """Test a is_new function created by build_detectors with a_node as a parent"""
#     is_renamed, _, _ = macos.build_detectors(base_tree.get_node(['a']))
#
#     # is rename is only true if the inode matches
#     assert is_renamed(name='renamed_a', props={'_inode': 'aa_node'})
#     assert not is_renamed(name='renamed_a', props={'_inode': 'other_node'})
#
#
# def test_renamed_from_in_sub_tree(base_tree):
#     """Test renamed_from created by build_detectors"""
#     _, renamed_from, _ = macos.build_detectors(base_tree.get_node(['a']))
#     node_a = base_tree.get_node(['a', 'a'])
#     assert renamed_from(name='renamed_a', props={'_inode': 'aa_node'}) == node_a

#
# def test_prune_tree(base_tree):
#     """Remove 'a' from root.
#
#     Expected:
#     ---------
#     c
#     """
#     macos.prune_tree(base_tree, keep=['c'])
#
#     assert not base_tree.has_child('a')
#     assert base_tree.has_child('c')
#     logger.info('base_tree after prune\n%s', bushn.tree_to_str(base_tree))


# def test_prune_sub_tree(base_tree):
#     """Remove 'a' from sub_tree.
#
#     Expected:
#     ---------
#     c
#     a
#     +-b
#     """
#     a_node = base_tree.get_node(['a'])
#     macos.prune_tree(a_node, keep=['b'])
#     assert base_tree.get_node(['a']).has_child('b')
#     assert base_tree.has_child('c')
#     logger.info('base_tree after prune\n%s', bushn.tree_to_str(base_tree))


def reset_mock(mock_to_reset):
    """Function to reset a mock.

    Simply because I have missspelt reset_mock once to often.
    And I can drop a sleep in there to make sure the reset catches the things I want.
    """
    time.sleep(.1)
    mock_to_reset.reset_mock()


def only_called(meth_name='storage_delete', event_sink=None, **kwargs):
    """Ensure that only one event is triggered on the event_sink.

    All others should not have been called.

    Remember to reset the mock prior to making the call you want to catch.
    """
    # wait for the methods to hit the mock
    time.sleep(.1)
    meth_map = {'storage_delete': event_sink.storage_delete,
                'storage_create': event_sink.storage_create,
                'storage_modify': event_sink.storage_modify}

    for name, meth in meth_map.items():
        if name == meth_name:
            meth.assert_called_once_with(**kwargs)
        else:
            meth.assert_not_called()
    return True


@pytest.fixture
def macos_fixture(tmpdir):
    """Combine tmpdir, macfs and event_sink into a ready to use fixture."""
    # push down down other output during testing with -s
    # print()

    event_sink = mock.Mock()
    macfs = Filesystem(root=str(tmpdir),
                       event_sink=event_sink,
                       storage_id=FILESYSTEM_ID)
    assert macfs.is_mac

    # reset the mock
    reset_mock(event_sink)
    macfs.start_events()
    yield tmpdir, macfs, event_sink
    macfs.stop_events()


def test_dir_added(macos_fixture):
    """Add a dir and ensure that storage_create is called."""
    # setup
    tmpdir, _, event_sink = macos_fixture

    # add dir
    test_dir = tmpdir.mkdir('test')
    expected_props = {'modified_date': mock.ANY,
                      'shared': False,
                      'version_id': 'is_dir',
                      'is_dir': True,
                      'size': mock.ANY}

    # assert
    assert only_called('storage_create',
                       event_sink=event_sink,
                       storage_id=FILESYSTEM_ID,
                       event_props=expected_props,
                       path=['test'])


def test_file_moved(macos_fixture):
    """Remove a dir and ensure it only calls storage_delete."""
    # setup
    tmpdir, macfs, event_sink = macos_fixture
    file_name = 'some_file.txt'
    source_dir = tmpdir.mkdir('source')
    dest_dir = tmpdir.mkdir('dest')
    the_file = source_dir.join(file_name)
    the_file.write('content')

    source_path = ['source', file_name]
    dest_path = ['dest', file_name]
    reset_mock(event_sink)

    # move
    the_file.move(target=dest_dir.join(file_name))

    # expect one create and one delete
    expected_props = {'modified_date': mock.ANY,
                      'is_dir': False,
                      'size': mock.ANY,
                      'shared': False,
                      'version_id': mock.ANY}

    expected_create = {'path': dest_path,
                       'storage_id': FILESYSTEM_ID,
                       'event_props': expected_props}

    expected_delete = {'path': source_path, 'storage_id': FILESYSTEM_ID}

    # assert
    time.sleep(.1)
    event_sink.storage_create.assert_called_once_with(**expected_create)
    event_sink.storage_delete.assert_called_once_with(**expected_delete)


def test_folder_inode_id(macos_fixture):
    """ tests if the inode id of a folder stays the same if files are written into it"""
    # getting fs and internal model
    tmpdir, macfs, event_sink = macos_fixture
    model = macfs.get_internal_model()

    # creating directory and checking calls ot sink
    a = tmpdir.mkdir('a')
    time.sleep(.1)
    event_sink.storage_create.assert_called_once()

    # resetting sink
    event_sink.reset_mock()

    # storing inode value for folder
    inode_folder_before = model.get_node_safe(['a']).props['_inode']

    # writing file to folder
    testfile = os.path.join(a.strpath, 'test.txt')
    with open(testfile, 'w') as file:
        file.write('asdfasfasfasf')

    # checking that called
    time.sleep(.1)
    assert len(model) == 3
    event_sink.storage_create.assert_called_once()

    # checking if inode_id in model is the same
    assert model.get_node_safe(['a']).props['_inode'] == inode_folder_before

    # checking if inode_id of folder is the same in fs
    assert os.stat(a.strpath).st_ino == inode_folder_before


def test_create_and_delete_file(macos_fixture):
    """tests that _update calls the right events"""
    tmpdir, macfs, event_sink = macos_fixture
    a = tmpdir.mkdir('a')
    b = a.mkdir('b')

    testfile = os.path.join(b.strpath, 'testfile.txt')
    with open(testfile, 'w') as file:
        file.write('blablablabalba')

    time.sleep(0.1)
    assert len(event_sink.method_calls) == 6

    os.unlink(testfile)
    time.sleep(0.1)
    event_sink.storage_delete.assert_called_once()


def test_mv_dir_to_sync_dir(macos_fixture, tmpdir):
    """Test move a directory with file to a sync dir.

    Test for issue CC_663
    """
    root_tmpdir, macfs, event_sink = macos_fixture
    directory = tmpdir.mkdir('my_dir')
    directory.join('some_text.txt').write_text('mycontent', 'utf-8')
    dir_in_sync_dir = root_tmpdir.mkdir('sp_dir')
    os.rename(str(directory), str(dir_in_sync_dir) + '/my_dir')
    time.sleep(2)
    print()
    print(event_sink.storage_create.call_args_list)
    event_sink.storage_create.assert_any_call(path=['sp_dir', 'my_dir'],
                                              event_props=mock.ANY, storage_id=mock.ANY)
    event_sink.storage_create.assert_any_call(path=['sp_dir', 'my_dir', 'some_text.txt'],
                                              event_props=mock.ANY, storage_id=mock.ANY)
