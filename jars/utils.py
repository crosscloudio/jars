"""
This is the place which should ease the development of storage providers
"""
import io
import logging
import time
from contextlib import ExitStack, contextmanager
import uuid
import unicodedata

import bushn
from bushn import IndexingNode, Node

import jars
from jars import CancelledException

logger = logging.getLogger(__name__)


class WriteToTempDirMixin:
    """ Mixin which writes to a tempfile and then moves everything to the right place """
    TEMPDIR = '.crosscloud-tmp'

    def write(self, path, file_obj, original_version_id=None, size=0):
        """ calls _pre_write and then write and then move, tries to cleanup everything
        in case something goes wrong """
        # todo: use size
        _ = size

        if hasattr(self, '_pre_write'):
            self._pre_write(path, file_obj, original_version_id)

        temp_path = [self.TEMPDIR, str(uuid.uuid1())]

        try:
            logger.debug("Writing to temp path %s", temp_path)
            version_id = self._write(temp_path, file_obj, None)
            logger.debug("done writing, moving from %s to %s", temp_path, path)
            version_id = self.move(temp_path, path, expected_source_vid=version_id,
                                   expected_target_vid=original_version_id)
            logger.debug("done moving from %s to %s", temp_path, path)
            return version_id
        except BaseException:
            logger.info('Cancelled write operation', exc_info=1)
            try:
                self.delete(temp_path, original_version_id=None)
            except FileNotFoundError:
                logger.info(
                    "Skipped deleting file %s (probably never was written)", temp_path)
            logger.info('Deleted templfile %s', temp_path)
            raise


class FilterEventSinkWrapper:
    """ Event sink wrapper which filters events"""

    def __init__(self, event_sink, filters):
        """initialiser"""
        self.event_sink = event_sink
        self.filters = filters

    def __getattr__(self, item):
        """regular getattr"""
        return getattr(self.event_sink, item)

    def storage_create(self, storage_id, path, event_props):
        """create event sink method"""
        if event_props.get('is_dir', False) and \
                does_path_change_filter(path, self.filters):
            # Trigger a filter update for this new folder
            parent = self.filters.get_node(path[:-1])
            parent.add_child(path[-1], {'children': True})

        if is_path_synced(path, self.filters, event_props.get('is_dir', False)):
            self.event_sink.storage_create(storage_id=storage_id, path=path,
                                           event_props=event_props)
        else:
            logger.debug("%s filtered", path)

    def storage_move(self, storage_id, source_path, target_path, event_props):
        """move event sink method"""
        if event_props.get('is_dir', False) and \
                does_path_change_filter(target_path, self.filters):
            # Trigger a filter update for this new folder
            parent = self.filters.get_node(target_path[:-1])
            parent.add_child(target_path[-1], {'children': True})

        if is_path_synced(target_path, self.filters, event_props.get('is_dir', False)):
            self.event_sink.storage_move(storage_id=storage_id,
                                         source_path=source_path, target_path=target_path,
                                         event_props=event_props)

    def storage_modify(self, storage_id, path, event_props):
        """modify event sink method"""
        if is_path_synced(path, self.filters, event_props.get('is_dir', False)):
            self.event_sink.storage_modify(storage_id=storage_id, path=path,
                                           event_props=event_props)

    def storage_delete(self, storage_id, path):
        """delete event sink method"""
        if is_path_synced(path, self.filters, False):
            self.event_sink.storage_delete(storage_id=storage_id, path=path)

        if any(f.path == path for f in self.filters):
            # This path was an entry in the filter list
            # --> update filters
            self.filters.get_node(path).delete()


class ControlFileWrapper(io.RawIOBase):
    """A class which can be wrapped around a file object to cancel read operations.

    TODO: This is copy pasted during the move to jars. Is there a better way to import?
    """

    def __init__(self, orig_obj, task, data_rate_callback=None):
        super().__init__()
        self._orig_obj = orig_obj
        self.task = task
        self.data_rate_callback = data_rate_callback
        self.read_count = 0

    def read(self, count=None):
        """Makes a transfer cancellable."""
        # check if it should be cancelled
        if self.task.cancelled:
            raise CancelledException('Cancelled while read')

        start_read_time = time.time()
        data = self._orig_obj.read(count)

        # submits the current datarate to the data_rate_callback
        if self.data_rate_callback:
            self.data_rate_callback(len(data) /
                                    time.time() - start_read_time)
        self.read_count += len(data)
        return data

    def tell(self):
        return self.read_count

    def seekable(self):
        return False

    def writable(self):
        return False


def get_node_safe(model, node_path):
    """Return node with path and creates intermediate nodes if necessary

    TODO: This is copy pasted from cc during the move to jars.
    Is there a better place for this?
    """
    parent = model
    node = None
    for path_elem in node_path:
        if parent.has_child(path_elem):
            node = parent.get_node([path_elem])
        else:
            node = parent.add_child(path_elem)
        parent = node
    return node


def normalize_path_element(elem):
    """
    Normalizes a path element to the internal representations.

    TODO: This was copy pasted during the move to jars. Is there a better place for this?

    :param elem: string
    :return: the normalized string

    """
    return unicodedata.normalize('NFKD', elem.casefold())


def normalize_path(path):
    """Normalizes the given path with unicode NFC and lower case

    TODO: This was copy pasted during the move to jars. Is there a better place for this?

    :param path: the path
    :return: the normalized path
    """
    new_path = []
    for elem in path:
        new_path.append(normalize_path_element(elem))
    return new_path


def config_to_tree(filter_config):
    """
    build a tree as helper to filter
    """
    filter_tree = Node(name=None)

    for filter_obj in filter_config:
        filter_tree.get_node_safe(filter_obj['path']).props.update(
            {'children': filter_obj['children']})
    return filter_tree


def tree_to_config(tree, children_default=True):
    """
    Converts the selected directories filter tree format to the dict format
    """
    for node in tree:
        yield {'children': node.props.get('children', children_default),
               'path': node.path}


def filter_tree_by_path(tree, filter_tree, children_default=True):
    """
    Copies the tree. It is filtered by the filters argument.

    :param tree: Tree to filter
    :param filters: The bool element states if the children on the same level should be
    included or not. If the filter for that item does not exist `children_default` is
    assumed. The filter with the longest path in a branch will also include all children
    recursively.
    :return: filtered tree
    """

    if isinstance(tree, IndexingNode):
        new_root = IndexingNode(name=None, indexes=tree.index.keys())
    else:
        new_root = type(tree)(name=None)

    for node in tree:
        if is_path_synced(node.path, filter_tree, node.props.get('is_dir', False),
                          children_default):
            new_root.get_node_safe(node.path).props.update(node.props)

    return new_root


def is_sub_path(path, filters):
    """
    returns if True if the path is on the same or on a lower level of one of the
    filters
    """
    return any([path[:len(fil)] == fil for fil in filters])


def is_part_of_path(path, filters):
    """
    returns True if the path is part of one of the filter paths
    """
    return any([path == f[:len(path)] for f in filters if len(path) < len(f)])


def is_path_synced(path, filter_tree, is_dir, children_default=True):
    """
    Checks if a path is filtered or has to be synced
    """
    # the closest node from bottom up
    filter_node = next(filter_tree.iter_up_existing(path))

    # the node path of the filter is equal to the current one
    longest_path = not bool(filter_node.children)
    # its parent has the children attribute set or

    parent_path = path[:-1]
    sync_child = (parent_path is not [] and
                  filter_node.path == parent_path and
                  filter_node.props.get('children', children_default) and
                  not is_dir)
    # if it is the longest path in the branch it has no children
    is_node = path == filter_node.path
    return longest_path or sync_child or is_node


def does_path_change_filter(path, filters):
    """
    Check if a event on a given path changes the filter
    """
    filter_node = next(filters.iter_up_existing(path))
    parent_path = path[:-1]
    return filter_node.path == parent_path and filter_node.children


@contextmanager
def emit_events(node, event_sink, storage_id):
    """Emit events to the event sink when the node is changed."""

    adapter = jars.TreeToSyncEngineEngineAdapter(node=node,
                                                 sync_engine=event_sink,
                                                 storage_id=storage_id)
    with ExitStack() as stack:
        stack.enter_context(adapter)
        yield


@contextmanager
def log_diff(tree, _logger, prop_key=None):
    """Log the tree before and after the opteration."""
    _logger.debug('+++ model pre update: \n%s\n +++',
                  bushn.tree_to_str(tree, prop_key=prop_key))
    yield
    _logger.debug('+++ model post update: \n%s\n +++',
                  bushn.tree_to_str(tree, prop_key=prop_key))
