"""
Unit tests for generic storage
"""

# pylint: disable=redefined-outer-name, unused-import

from functools import partial

import mock
import pytest

from jars import NoSpaceError
from jars.utils import FilterEventSinkWrapper, config_to_tree, filter_tree_by_path
import bushn


@pytest.fixture(params=[True, False])
def root(request):
    """Create a default Root node

    TODO: Copy pasted during move to jars. Is there a better place?
    :return: Node
    """
    if request.param:
        return bushn.Node(name=None)
    else:
        return bushn.IndexingNode(name=None, indexes=['_id'])


@pytest.fixture(params=[True, False])
def default_root(root, request):
    """Create a default Root node.

    TODO: Copy pasted during move to jars. Is there a better place?
    """
    if request.param:
        return root
    else:
        new_root = root.create_instance()
        root.parent = new_root
        root.name = 'old_root'
        return new_root


def test_no_space_error():
    """
    Test for no space exception.
    """
    no_space_error = NoSpaceError(storage_id='st_id', origin_error=None, free_space=40)
    assert no_space_error.free_space == 40


@pytest.fixture()
def event_sink():
    """
    setup mocked event sink wrapper which is able to monitor function calls
    """
    orig_event_sink = mock.MagicMock()
    orig_event_sink.storage_modify = mock.MagicMock()
    orig_event_sink.storage_create = mock.MagicMock()
    orig_event_sink.storage_delete = mock.MagicMock()
    orig_event_sink.storage_move = mock.MagicMock()

    filters = config_to_tree([{'children': True, 'path': []},
                              {'children': True, 'path': ['a']},
                              {'children': True, 'path': ['a', 'b']}])
    event_sink = FilterEventSinkWrapper(orig_event_sink, filters)
    return event_sink


@pytest.mark.parametrize('method, event_props, filter_update',
                         [('modify', {'is_dir': False}, False),
                          ('create', {'is_dir': False}, False),
                          ('create', {'is_dir': True}, True),
                          ('delete', {}, False)])
def test_filter_event_sink_wrapper(event_sink, method, event_props, filter_update):
    """
    This test checks if all possible method calls in the filtering event sink
    are correctly forwarded or filtered
    """
    result_sink = event_sink.event_sink
    origin_func = None
    result_func = None

    func_params = {'storage_id': 'csp_1', 'event_props': event_props}

    if method == 'modify':
        origin_func = event_sink.storage_modify
        result_func = result_sink.storage_modify
    elif method == 'create':
        origin_func = event_sink.storage_create
        result_func = result_sink.storage_create
    elif method == 'delete':
        origin_func = event_sink.storage_delete
        result_func = result_sink.storage_delete
        del func_params['event_props']

    filter_changed_func = register_signal_handler(event_sink)

    func_params['path'] = ['a', 'b', 'c']
    origin_func(**func_params)
    result_func.assert_called_once_with(**func_params)
    result_func.reset_mock()

    func_params['path'] = ['a', 'c', 'c']

    origin_func(**func_params)
    result_func.assert_not_called()
    result_func.reset_mock()

    func_params['path'] = ['a', 'c']
    origin_func(**func_params)
    result_func.assert_called_once_with(**func_params)
    result_func.reset_mock()

    if filter_update:
        filter_changed_func.assert_called()
    else:
        filter_changed_func.assert_not_called()


def test_filter_event_sink_wrapper_delete(event_sink):
    """
    Tests the delete event which should also trigger a filter update
    :param event_sink:
    :return:
    """
    filter_changed_func = register_signal_handler(event_sink)

    result_sink = event_sink.event_sink
    func_params = {'storage_id': 'csp_1', 'path': ['a', 'b']}
    event_sink.storage_delete(**func_params)
    result_sink.storage_delete.assert_called_once_with(**func_params)

    with pytest.raises(KeyError):
        event_sink.filters.get_node(['a', 'b'])

    filter_changed_func.assert_called_once()


@pytest.mark.parametrize('path, filter_update', [(['a', 'b', 'c'], False),
                                                 (['a', 'c'], True),
                                                 (['b'], True)])
def test_filter_event_sink_wrapper_create(event_sink, path, filter_update):
    """
    Tests the create event which should also trigger a filter update
    :param event_sink:
    :return:
    """
    result_sink = event_sink.event_sink
    filter_changed_func = register_signal_handler(event_sink)
    func_params = {'storage_id': 'csp_1', 'path': path,
                   'event_props': {'is_dir': True}}
    event_sink.storage_create(**func_params)
    result_sink.storage_create.assert_called_once_with(**func_params)
    result_sink.storage_create.reset_mock()

    if filter_update:
        event_sink.filters.get_node(path)
        filter_changed_func.assert_called_once()
    else:
        with pytest.raises(KeyError):
            event_sink.filters.get_node(path)
        filter_changed_func.assert_not_called()


def test_filter_event_sink_wrapper_move(event_sink):
    """
    Tests the create event which should also trigger a filter update
    :param event_sink:
    :return:
    """
    result_sink = event_sink.event_sink
    filter_changed_func = register_signal_handler(event_sink)

    # this is a folder so it will be added to the filters
    func_params = {'storage_id': 'csp_1', 'source_path': ['a', 'b', 'c'],
                   'target_path': ['a', 'c'], 'event_props': {'is_dir': True}}

    event_sink.storage_move(**func_params)

    result_sink.storage_move.assert_called_once_with(**func_params)
    result_sink.storage_move.reset_mock()

    event_sink.filters.get_node(['a', 'c'])
    filter_changed_func.assert_called_once()
    filter_changed_func.reset_mock()

    # this is a file so it will not be added to the filters
    func_params = {'storage_id': 'csp_1', 'source_path': ['a', 'b', 'c'],
                   'target_path': ['a', 'd'], 'event_props': {'is_dir': False}}
    event_sink.storage_move(**func_params)

    result_sink.storage_move.assert_called_once_with(**func_params)
    result_sink.storage_move.reset_mock()

    with pytest.raises(KeyError):
        event_sink.filters.get_node(['a', 'd'])
    filter_changed_func.assert_not_called()


@pytest.mark.skip
def test_filter_config_update(event_sink):
    """Tests the create event which should also trigger a filter update

    TODO: rethink if this should be a test in cc or in jars.
    :param event_sink:
    :return:
    """
    # pylint: disable=all
    pytest.skip("This is to complexted with cc to be in jars.")
    with mock.patch('cc.config.write_config', mock.Mock()):
        with mock.patch('cc.config.csps', [{'id': 'csp_1'}]):
            update_func = partial(cc.config.update_filter_in_config, csp_id='csp_1')
            event_sink.filters.on_update.connect(update_func)
            event_sink.filters.on_delete.connect(update_func)
            event_sink.filters.on_create.connect(update_func)
            func_params = ['csp_1', ['a', 'c'], {'is_dir': True}]
            event_sink.storage_create(*func_params)

            assert cc.config.csps[0]['id'] == 'csp_1'
            expected = [
                {'children': True, 'path': ['a', 'b']},
                {'children': True, 'path': ['a', 'c']},
                {'children': True, 'path': ['a']},
                {'children': True, 'path': []}]
            assert all(
                elem in expected for elem in cc.config.csps[0]['selected_sync_directories'])


def register_signal_handler(event_sink):
    """
    Registers a mock function to the event sink
    :param event_sink:
    :return: the mocked function
    """

    def dummy_func():
        """
        we need that for connecting a mock to a blinker signal
        http://stackoverflow.com/questions/19569164/
        """
        pass

    filter_changed_func = mock.MagicMock(spec=dummy_func)
    event_sink.filters.on_update.connect(filter_changed_func)
    event_sink.filters.on_delete.connect(filter_changed_func)
    event_sink.filters.on_create.connect(filter_changed_func)
    return filter_changed_func


def create_binary_tree(node, levels):
    """
    :return: Binary tree with levels childs
    """
    if levels <= 0:
        return

    for child_num in range(2):
        create_binary_tree(
            node.add_child('{}'.format(child_num)), levels - 1)
        node.props.update({'level': levels})


def test_filter_tree(default_root):
    """
    Tests an inclusive filter set for root
    """
    create_binary_tree(default_root, 4)
    filter_config = [{'children': False, 'path': []}]
    filter_tree = config_to_tree(filter_config)
    other = filter_tree_by_path(default_root, filter_tree)

    assert default_root.subtree_equals(other)


def test_filter_tree_filter(default_root):
    """
    Tests an inclusive filter set for one half of the binary tree
    """
    create_binary_tree(default_root, 4)
    filter_config = [{'children': False, 'path': []}, {'children': False, 'path': ['0']}]
    filter_tree = config_to_tree(filter_config)
    other = filter_tree_by_path(default_root, filter_tree)

    assert not other.has_child('1')
    assert default_root.get_node(['0']).subtree_equals(other.get_node(['0']))


def test_filter_tree_filter_deep(default_root):
    """
    Tests the tree filtering
    """
    create_binary_tree(default_root, 4)
    filter_config = [{'children': False, 'path': ['0']},
                     {'children': False, 'path': ['1', '0']},
                     {'children': False, 'path': ['1']}]
    filter_tree = config_to_tree(filter_config)
    other = filter_tree_by_path(default_root, filter_tree)

    # node ['1', '1'] should not exist since the rule (False, ['1']) excludes that
    assert not other.get_node(['1']).has_child('1')
    assert other.get_node(['1']).props == {'level': 3}
    assert default_root.get_node(['0']).subtree_equals(other.get_node(['0']))
    assert default_root.get_node(['1', '0']).subtree_equals(other.get_node(['1', '0']))


def test_filter_tree_filter_root_children(default_root):
    """ The root path still should have [0] as children but nothing below """
    create_binary_tree(default_root, 4)
    filter_config = [{'children': True, 'path': []},
                     {'children': False, 'path': ['1', '0']}]
    filter_tree = config_to_tree(filter_config)
    other = filter_tree_by_path(default_root, filter_tree)

    assert other.has_child('0')
    assert not other.get_node(['0']).has_child('0')
    assert other.get_node(['1']).has_child('1')
    assert not other.get_node(['1', '1']).has_child('1')
    assert other.get_node(['1']).props == {'level': 3}
    assert default_root.get_node(['1', '0']).subtree_equals(other.get_node(['1', '0']))


def test_filter_tree_filter_root_props(default_root):
    """ See if the props of the root are copied """
    create_binary_tree(default_root, 4)
    filter_config = [{'children': True, 'path': []}]
    filter_tree = config_to_tree(filter_config)
    other = filter_tree_by_path(default_root, filter_tree)
    assert other.props == {'level': 4}


def test_config_to_filter():
    """
    Tests the transformation of a dict-filter config into a tree config
    """
    config = [{"children": True, "path": ["a"]}, {"children": True, "path": []}]
    filter_tree = config_to_tree(config)
    assert filter_tree.get_node(['a']).props['children']
