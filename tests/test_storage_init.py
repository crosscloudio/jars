""" the __init__ in the package file """

from functools import partial

import mock

from jars import BasicStorage
from bushn import Node


class BinaryTreeGetter:
    """ to enable testing with less boilerplate this function is a substitute for
    get_tree_children generating a binary tree with depth `depth`"""

    def __init__(self, depth):
        self.depth = depth

    def __call__(self, path):
        assert len(path) < self.depth + 1, 'oh snap, there is nothing'

        return [('a', {'is_dir': len(path) < self.depth}),
                ('b', {'is_dir': len(path) < self.depth}),
                ('c', {'is_dir': False})]


def test_get_tree_one_node():
    """ tests adding one single node """
    storage_mock = mock.Mock()
    storage_mock.get_tree_children = mock.Mock(
        return_value=[('hello', {'is_dir': False})])

    storage_mock.filter_tree = Node(name=None)

    tree = BasicStorage.get_tree(storage_mock)

    assert tree.get_node(['hello']).props == {'is_dir': False}


def test_get_tree_two_children():
    """ tests adding a binary tree with the depth of 4 """
    # this enabled a recursive call of get_tree
    storage_mock = mock.Mock(spec=BasicStorage)
    storage_mock.get_tree = partial(BasicStorage.get_tree, storage_mock)

    storage_mock.filter_tree = Node(name=None)

    storage_mock.get_tree_children = mock.Mock(side_effect=BinaryTreeGetter(2))

    tree = BasicStorage.get_tree(storage_mock)

    assert tree.get_node(['a']).props == {'is_dir': True}
    assert tree.get_node(['b']).props == {'is_dir': True}
    assert tree.get_node(['a', 'a']).props == {'is_dir': True}
    assert tree.get_node(['a', 'a', 'a']).props == {'is_dir': False}


def test_get_tree_filter():
    """ tests the tree with a a filter set on selected_sync_dirs """
    # this enabled a recursive call of get_tree
    storage_mock = mock.Mock(spec=BasicStorage)
    storage_mock.get_tree = partial(BasicStorage.get_tree, storage_mock)

    storage_mock.get_tree_children = mock.Mock(side_effect=BinaryTreeGetter(2))

    storage_mock.filter_tree = Node(name=None)
    storage_mock.filter_tree.add_child('a').add_child('a').add_child('a')

    tree = BasicStorage.get_tree(storage_mock)

    # b should be filtered since it is a directory
    assert not tree.has_child('b')
    assert not tree.get_node(['a']).has_child('b')

    # c should not be filtered since it is a file in a flat-observed directory
    assert tree.has_child('c')
    assert tree.get_node(['a', 'c'])
    assert tree.get_node(['a', 'a']).has_child('a')
    assert tree.get_node(['a', 'a']).has_child('b')
    assert tree.get_node(['a', 'a']).has_child('c')
