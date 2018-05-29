""" Test module, testing :class:`jars.TreeoSyncEngineEngineAdapter`"""
import datetime
import mock
import pytest

import jars
import bushn

TEST_STORAGE_ID = 'test_storage'

TEST_DATE = datetime.datetime.utcnow()

TEST_PROPS = {'version_id': 'Fisch',
              'is_dir': False,
              'size': 123,
              'modified_date': TEST_DATE,
              'shared': False}


# pylint: disable=redefined-outer-name

@pytest.fixture
def tree_adapter():
    """ simple tree adapter with one node in the root """
    tree_root = bushn.Node(None)
    se_mock = mock.Mock()
    adapter = jars.TreeToSyncEngineEngineAdapter(tree_root, se_mock,
                                                 storage_id=TEST_STORAGE_ID)
    with adapter:
        tree_root.add_child('Hello', props=TEST_PROPS)
    return tree_root, se_mock, adapter


def test_create(tree_adapter):
    """ test if `storage_create` is called directly """
    # todo: write a test where it will not call create because properties are incomplete

    tree_root, se_mock, _ = tree_adapter
    se_mock.storage_create.assert_called_once_with(
        storage_id=TEST_STORAGE_ID,
        path=['Hello'],
        event_props=TEST_PROPS)

    se_mock.storage_modify.assert_not_called()

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_create.call_args[1]['path'] is not list(tree_root.children)[
        0].path
    assert se_mock.storage_create.call_args[1]['event_props'] is not list(
        tree_root.children)[0].props


def test_delete(tree_adapter):
    """ test if `storage_delete` is called directly """
    tree_root, se_mock, adapter = tree_adapter
    thenode = tree_root.get_node(['Hello'])

    with adapter:
        thenode.delete()

    se_mock.storage_delete.assert_called_once_with(storage_id=TEST_STORAGE_ID,
                                                   path=['Hello'])

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_delete.call_args[1]['path'] is not thenode.path


def test_delete_recursive(tree_adapter):
    """ test if `storage_delete` is called for all children of a node """
    pytest.skip("since we do not recusively delete anymore")
    tree_root, se_mock, adapter = tree_adapter
    thenode = tree_root.get_node(['Hello'])
    thenode.add_child('subnode1')
    thenode.add_child('subnode2')

    with adapter:
        thenode.delete()

    se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
                                           path=['Hello'])
    se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
                                           path=['Hello', 'subnode1'])
    se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
                                           path=['Hello', 'subnode2'])

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_delete.call_args[1]['path'] is not thenode.path


def test_rename(tree_adapter):
    """ tests if a rename calles `storage_move` correctly """
    tree_root, se_mock, adapter = tree_adapter
    thenode = tree_root.get_node(['Hello'])
    se_mock.storage_create.reset_mock()

    old_path = thenode.path
    with adapter:
        thenode.name = 'a brand new name'

    se_mock.storage_move.assert_called_once_with(
        storage_id=TEST_STORAGE_ID, source_path=['Hello'], target_path=['a brand new name'],
        event_props=thenode.props)

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_move.call_args[1]['source_path'] is not thenode.path
    # even not the old path
    assert se_mock.storage_move.call_args[1]['target_path'] is not old_path

    assert se_mock.storage_move.call_args[1]['event_props'] is not thenode.props


# def test_rename_recursive(tree_adapter):
#     """ test if `storage_delete` is called for all children of a node """
#     tree_root, se_mock, adapter = tree_adapter
#     thenode = tree_root.get_node(['Hello'])
#     subnode1 = thenode.add_child('subnode1', {'a': 'b'})
#     subnode1.add_child('subnode2', {'c': 'd'})
#
#     with adapter:
#         thenode.name = 'World'
#
#     se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['Hello'])
#     se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['Hello', 'subnode1'])
#     se_mock.storage_delete.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['Hello', 'subnode1', 'subnode2'])
#
#     se_mock.storage_create.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['World'],
#                                            event_props=TEST_PROPS)
#     se_mock.storage_create.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['World', 'subnode1'],
#                                            event_props={'a': 'b'})
#     se_mock.storage_create.assert_any_call(storage_id=TEST_STORAGE_ID,
#                                            path=['World', 'subnode1', 'subnode2'],
#                                            event_props={'c': 'd'})


def test_move(tree_adapter):
    """ tests if a move calles `storage_move` correctly """
    tree_root, se_mock, adapter = tree_adapter
    thenode = tree_root.get_node(['Hello']).add_child('World')

    se_mock.storage_create.reset_mock()

    old_path = thenode.path

    new_parent = tree_root.add_child('a new home')
    with adapter:
        thenode.parent = new_parent

    se_mock.storage_move.assert_called_once_with(storage_id=TEST_STORAGE_ID,
                                                 source_path=['Hello', 'World'],
                                                 target_path=['a new home', 'World'],
                                                 event_props=thenode.props)

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_move.call_args[1]['target_path'] is not thenode.path
    assert se_mock.storage_move.call_args[1]['event_props'] is not thenode.props

    # even not the old path
    assert se_mock.storage_move.call_args[1]['source_path'] is not old_path


def test_move_recursive(tree_adapter):
    """ test if `storage_move` is called for all children of a node and itself """
    tree_root, se_mock, adapter = tree_adapter
    thenode = tree_root.get_node(['Hello'])
    thenode.add_child('subnode1', {'a': 'b'}).add_child('subnode2', {'c': 'd'})

    newparent = tree_root.add_child('newy').add_child('parent')

    with adapter:
        thenode.parent = newparent

    se_mock.storage_move.assert_any_call(storage_id=TEST_STORAGE_ID,
                                         source_path=['Hello'],
                                         target_path=['newy', 'parent', 'Hello'],
                                         event_props=TEST_PROPS)

    # we do not allow to have references passed into the sync engine
    assert se_mock.storage_move.call_args[1]['target_path'] is not thenode.path


def test_update(tree_adapter):
    """ tests if a update calles `storage_modify` correctly """
    tree_root, se_mock, adapter = tree_adapter
    thenode = list(tree_root.children)[0]
    with adapter:
        thenode.props['version_id'] = 123321

    se_mock.storage_modify.assert_called_once_with(storage_id=TEST_STORAGE_ID,
                                                   path=thenode.path,
                                                   event_props=thenode.props)

    assert se_mock.storage_modify.call_args[1]['path'] is not thenode.path
    assert se_mock.storage_modify.call_args[1]['event_props'] is not thenode.props


def test_filter_root(tree_adapter):
    """ tests if the root node is not propergated to the sync_engine """
    tree_root, se_mock, adapter = tree_adapter

    with adapter:
        tree_root.props['abc'] = 123

    se_mock.storage_modify.assert_not_called()


VALID_PROPS = {'is_dir': False, 'size': 123, 'version_id': 123, 'shared': False,
               'modified_date': datetime.datetime.now()}


def test_check_storage_properties():
    """ tests if the properties are correctly checked """
    assert jars.check_storage_properties(VALID_PROPS)
    assert not jars.check_storage_properties({})


@pytest.mark.parametrize('prop', sorted(VALID_PROPS.keys()))
def test_check_storage_properties_missing(prop):
    """ tests if the properties are correctly field checked """
    props = VALID_PROPS.copy()
    del props[prop]
    assert not jars.check_storage_properties({})


@pytest.mark.parametrize('prop', sorted(VALID_PROPS.keys()))
def test_check_storage_properties_invalid_type(prop):
    """ tests if the properties are correctly type checked """
    if prop == 'version_id':
        pytest.skip('version_id can by any type')
    props = VALID_PROPS.copy()
    props[prop] = object()
    assert not jars.check_storage_properties({})
