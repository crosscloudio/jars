"""This module provides functinality to watch the macOS filesystem."""
# pylint: disable=no-name-in-module
# pylint: disable=abstract-method
# pylint: disable=unused-argument
# pylint: disable=too-many-locals
import contextlib
import copy
import logging
import os
from datetime import datetime as dt

from fsevents import Observer, Stream

import jars
from jars import METRICS
from jars.fs.filesystem import FilesystemBasic
from jars.fs.filesystem import cc_path_to_fs
from jars.fs.filesystem import file_ignored
from jars.fs.filesystem import fs_to_cc_path
from jars.fs.filesystem import get_eventprops_from_stat
from jars import TreeToSyncEngineEngineAdapter
from bushn import tree_to_str, Node
from . import constants

logger = logging.getLogger(__name__)


def is_(flag, mask):
    """Check if flag is set in the mask."""
    return bool(mask & flag)


class FSEvent:
    """Wrap the fs_event and provid helper methods to increase readability.

    Args:
        :param path: absolute path which caused this event.
        :param mask: bit mask of attributes set for this event.
        :param event_id: internal id of the event.
        :type path: string
        :type mask: int
        :type event_id: int
    """

    __slots__ = ['path', 'mask', 'event_id']

    def __init__(self, path, mask, event_id):
        """Initialize a FSEvent by setting the values of the slots."""
        self.path = path
        self.mask = mask
        self.event_id = event_id

    def __repr__(self):
        """Return a multiline repr, usefull for debugging.

        It outputs the various flags set for this event based on the mask attribute.
        Certain flags have been comented out in the `show` list, to reduce clutter.

        Example:
        --------
        FSEvent for /full/path/to/the_file
        is_create    |     is_dir      |     is_file     |     is_mod
            1        |        1        |        0        |        0
        """
        show = ['is_create',
                'is_dir',
                # 'is_file',
                'is_mod',
                'is_renamed',
                'is_removed',
                # 'is_itemxattrmod',
                # 'is_inode_meta_mod',
                # 'is_symlink'
                # 'finder_info_has_changed',
                # 'has_changed_owner',
                ]
        head_list = [' {:^15} |'.format(name) for name in show]
        temp_list = [' {' + name + ':^15} |' for name in show]
        template = '\n'.join(
            ['FSEvent for {path} {mask}', ''.join(head_list), ''.join(temp_list)])

        kwargs = {name: getattr(self, name) for name in show}

        return template.format(path=self.path, mask=self.mask, **kwargs)

    @property
    def is_dir(self):
        """Check if the ITEMISDIR flag is set."""
        return is_(constants.FS_ITEMISDIR, self.mask)

    @property
    def is_create(self):
        """Check if the FS_ITEMCREATED flag is set."""
        return is_(constants.FS_ITEMCREATED, self.mask)

    @property
    def is_removed(self):
        """Check if the FS_ITEMREMOVED flag is set."""
        return is_(constants.FS_ITEMREMOVED, self.mask)

    @property
    def is_inode_meta_mod(self):
        """Check if the FS_ITEMINODEMETAMOD flag is set."""
        return is_(constants.FS_ITEMINODEMETAMOD, self.mask)

    @property
    def is_renamed(self):
        """Check if the FS_ITEMRENAMED flag is set."""
        return is_(constants.FS_ITEMRENAMED, self.mask)

    @property
    def is_mod(self):
        """Check if the FS_ITEMMODIFIED flag is set."""
        return is_(constants.FS_ITEMMODIFIED, self.mask)

    @property
    def finder_info_has_changed(self):
        """Check if the FS_ITEMFINDERINFOMOD flag is set."""
        return is_(constants.FS_ITEMFINDERINFOMOD, self.mask)

    @property
    def has_changed_owner(self):
        """Check if the FS_ITEMCHANGEOWNER flag is set."""
        return is_(constants.FS_ITEMCHANGEOWNER, self.mask)

    @property
    def is_itemxattrmod(self):
        """Check if the FS_ITEMXATTRMOD flag is set."""
        return is_(constants.FS_ITEMXATTRMOD, self.mask)

    @property
    def is_file(self):
        """Check if the FS_ITEMISFILE flag is set."""
        return is_(constants.FS_ITEMISFILE, self.mask)

    @property
    def is_symlink(self):
        """Check if the FS_ITEMISSYMLINK flag is set."""
        return is_(constants.FS_ITEMISSYMLINK, self.mask)

    def cc_path(self, cc_root):
        """Convert path to the path list used inside bushn.Node."""
        return fs_to_cc_path(self.path, root_path=cc_root)

    def sp_dir(self, cc_root):
        """Return the part of the path which describes the sp_dir."""
        return [self.cc_path(cc_root)[0]]

    def is_sp_dir(self, cc_root):
        """Check if this event pertains to a storage provider directory."""
        return self.is_dir and \
            self.sp_dir(cc_root) == self.cc_path(cc_root)

    @property
    def path_exists(self):
        """Check if the event path still exist."""
        return os.path.exists(self.path)


class MacOSFileBaseSystem(FilesystemBasic):
    """MacOS specific Filesystem."""

    is_mac = True
    """Used for testing to ensure that the Filesystem does subclass this class."""

    observer = None
    """The observer which is instantiated in start_events."""

    @property
    def real_root(self):
        """Return the realpath of the root.

        fs_events paths are realpaths. i.e.: without symlinks.
        """
        return os.path.realpath(self.root)

    def fsevent_handler(self, path, mask, _id):
        """Handle events from fsevents, get the current directory content and update the model.

        Args:
            :param path: absolute path which caused this event.
            :param mask: bit mask of attributes set for this event.
            :param _id: internal id of the event.
            :type path: string
            :type mask: int
            :type _id: int

        ..Note: The flags on these events are badly/not documented. Log the events to make
        sure which flags are actualy set. Do not trust your intuition.

        After preliminary checks, the path is handed to self._update, to trigger the necessary
        events.
        """
        event = FSEvent(path=path, mask=mask, event_id=_id)

        if file_ignored(event.path):
            logger.debug('Event ignored for %s', path)
            return

        cc_path = event.cc_path(self.real_root)
        if cc_path == ['.']:
            cc_path = []
        logger.info('update for %s', cc_path)
        try:
            self._update(cc_path)
        except BaseException:
            logger.debug('got exception while processing FSEvents %s', exc_info=True)

    def _update(self, cc_path):
        """Inspect the directory to detect what has changed since the last call to `_update`.

        Args:
            :param cc_path: path of directory to update.
            :type cc_path: list of strings.
        """
        logger.info('_update for %s for tree %s', cc_path, self.model)

        # ignore event if parent directory no longer exists on the fs
        parent_folder = cc_path_to_fs(cc_path[:-1], self.real_root)
        if not os.path.exists(parent_folder):
            logger.debug('Event ignored: parent folder no longer exist')
            return

        with TreeToSyncEngineEngineAdapter(node=self.model, storage_id=self.storage_id,
                                           sync_engine=self._event_sink):
            # Ensure that the path exists in the model.
            parent = self.model
            for idx, name in enumerate(cc_path):
                if parent.has_child(name):
                    parent = parent.get_node([name])
                else:
                    partial_cc_path = cc_path[:idx + 1]
                    parent = parent.add_child(name, props=self.get_props(partial_cc_path))

            directory = cc_path_to_fs(cc_path, self.real_root)

            new_inodes = {props['_inode']: (name, props)
                          for name, props in self.get_tree_children(cc_path)}
            old_inodes = {node.props['_inode']: node for node in parent.children}

            new_inodes_set = new_inodes.keys()
            old_inodes_set = old_inodes.keys()

            inode_intersection = new_inodes_set & old_inodes_set
            removed_inodes = old_inodes_set - new_inodes_set
            added_inodes = new_inodes_set - old_inodes_set

            for inode in inode_intersection:
                old_node = old_inodes[inode]
                new_node_name, new_node_props = new_inodes[inode]

                old_node.props.update(new_node_props)
                old_node.name = new_node_name

            for inode in removed_inodes:
                # TODO: might be moved to a different dir, might be deleted
                old_inodes[inode].delete()

            for inode in added_inodes:
                new_node_name, new_node_props = new_inodes[inode]
                new_node = parent.add_child(new_node_name, new_node_props)
                if new_node_props[jars.IS_DIR]:
                    self._update(new_node.path)

    def start_events(self):
        """Setup the observer."""
        self.get_tree(cached=False)
        if self.observer is None:
            self.observer = Observer()
        stream = Stream(self.fsevent_handler, self.real_root, ids=True)
        self.observer.schedule(stream)

        if not self.observer.is_alive():
            self.observer.start()

    def stop_events(self, *args, **kwargs):
        """Call stop() on the observer."""
        self.update()
        if self.observer is not None:
            self.observer.stop()

    def clear_model(self):
        """Reset the model to only contain one root node."""
        self.model = Node(None)

    def get_tree(self, cached=False):
        """Return a deep copy of the internal model."""
        if cached:
            return copy.deepcopy(self.model)
        else:
            return super().get_tree(cached=False)

    def update(self):
        """Update the internal model, by walking the directory structure of the root."""
        self.model = self.get_tree()

    def get_internal_model(self):
        """Return the current internal model, used in testing."""
        return self.model
