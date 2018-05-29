"""
Storage implementation for the FileSystem
"""

# pylint: disable=abstract-method,wrong-import-order
import datetime
import fnmatch
import threading
import shutil
import stat
import unicodedata
import logging
import os

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from jars import BasicStorage, VersionIdNotMatchingError, StorageMetrics, METRICS, \
    remove_private_props, InvalidOperationError
import jars.utils

logger = logging.getLogger(__name__)
IGNORED_FILENAMES = ['Thumbs.db', 'ehthumbs.db', 'Desktop.ini', '$RECYCLE.BIN', '*.lnk',
                     '.DS_Store', '.AppleDouble', '.LSOverride', '~*',
                     '.DocumentRevisions-V100',
                     '.fseventsd', '.Spotlight-V100', '.TemporaryItems', '.Trashes',
                     '.VolumeIcon.icns', '.AppleDB', '.AppleDesktop',
                     'Netwopeprk Trash Folder', 'Temporary Items', '.apdisk', '*~',
                     '.fuse_hidden*', '.directory', '.Trash-*',
                     '.crosscloud-tmp', '.crosscloud-tmp/**', '**/.crosscloud-tmp/**']


class FilesystemBasic(BasicStorage):
    """
    File System Storage for POSIX case ignorant systems: Mac osx ;)
    """

    auth = [BasicStorage.AUTH_NONE]

    storage_name = 'filesystem'
    storage_display_name = 'File System'

    def __init__(self, root, event_sink, storage_id, obs_handler=None):
        """
        constructor
        :param root: the root dir to watch (root of this storage)
        :param event_sink: the event sink to which report change events to
        :param storage_id: the unique id of the storage
        :param obs_handler: the handler for producing events (default = Watcher)
        """
        super().__init__(event_sink=event_sink, storage_id=storage_id)
        logger.debug(event_sink)
        self.root = root
        self.obs = None
        if obs_handler is not None:
            self.obs_handler = obs_handler
        else:
            self.obs_handler = None

        self.replace_operations = set()
        self.replace_operations_lock = threading.Lock()
        self.event_sink = self._event_sink

    def start_events(self):
        if self.obs is None:
            self.obs = Observer()
        if self.obs_handler is None:
            self.obs_handler = FileSystemWatcher(self)

        self.obs.schedule(self.obs_handler, self.root, recursive=True)
        if not self.obs.is_alive():
            self.obs.start()

    def stop_events(self, join=False):
        """stops the mechanism producing event for changes if present"""
        if self.obs_handler is not None:
            self.obs.stop()

    def make_dir(self, path):
        fs_path = cc_path_to_fs(path, self.root)
        if not os.path.isdir(self.root):
            raise InvalidOperationError('Root directory does not exist any longer')
        os.makedirs(fs_path, exist_ok=True)
        return 'is_dir'

    def open_read(self, path, expected_version_id=None):
        fs_path = cc_path_to_fs(path, self.root)

        props = get_eventprops_from_stat(fs_path)
        if expected_version_id and props['version_id'] != expected_version_id:
            raise VersionIdNotMatchingError(
                storage_id=self.storage_id, version_a=props['version_id'],
                version_b=expected_version_id)

        return open(fs_path, 'rb')

    def _write(self, path, file_obj, original_version_id=None):
        # defining write chunk size
        write_chunk_size = 1024 * 512

        # getting path to write to
        fs_path = cc_path_to_fs(path, self.root)

        # creating dir if not there
        self.make_dir(path[:-1])

        # checking that intended version id is the one we see now -> otherwise the
        # item has been modified in between and we don't want to overwrite this
        if original_version_id:
            if get_eventprops_from_stat(fs_path)['version_id'] != original_version_id:
                raise VersionIdNotMatchingError(self.storage_id)

        # read the first chunk in advance to check if its a encrypted files
        chunk = file_obj.read(write_chunk_size)

        # not encrypted data -> writing to filesystem
        with open(fs_path, 'wb') as file_target:
            while chunk:
                file_target.write(chunk)
                chunk = file_obj.read(write_chunk_size)

        # getting props from written file
        stat_result = get_eventprops_from_stat(fs_path)

        # returning the version id of the new element written
        return stat_result['version_id']

    def _pre_write(self, path, file_obj, original_version_id):
        """
        called by the mixin
        """

        _ = file_obj
        _ = original_version_id

        fs_path = cc_path_to_fs(path, self.root)

        if os.path.exists(fs_path):
            with self.replace_operations_lock:
                self.replace_operations.add(tuple(path))

    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        fs_path_src = cc_path_to_fs(source, self.root)
        fs_path_target = cc_path_to_fs(target, self.root)

        props = get_eventprops_from_stat(fs_path_src)

        if expected_source_vid:
            if props['version_id'] != expected_source_vid:
                raise VersionIdNotMatchingError(storage_id=self.storage_id,
                                                version_a=props['version_id'],
                                                version_b=expected_source_vid)

        if expected_target_vid:
            props_target = get_eventprops_from_stat(fs_path_target)
            if props_target['version_id'] != expected_target_vid:
                raise VersionIdNotMatchingError(storage_id=self.storage_id,
                                                version_a=props_target['version_id'],
                                                version_b=expected_target_vid)

        assert not os.path.isdir(fs_path_target)

        # create a directory implicitly for the path except the last portion
        self.make_dir(target[:-1])
        shutil.move(fs_path_src, fs_path_target)

        stat_result = get_eventprops_from_stat(fs_path_target)
        return stat_result['version_id']

    def delete(self, path, original_version_id):
        fs_path = cc_path_to_fs(path, self.root)

        if original_version_id is not None:
            props = get_eventprops_from_stat(fs_path)
            if props['version_id'] != original_version_id:
                raise VersionIdNotMatchingError(storage_id=self.storage_id)

        logger.debug(path[0])
        if os.path.isdir(fs_path):
            shutil.rmtree(fs_path)
        else:
            os.unlink(fs_path)

    def get_metrics(self):
        """ returns a StorageMetrics object. Here its is based on posix statvfs """
        # on windows there is no os.statvfs
        # pylint: disable=no-member
        stats = os.statvfs(self.root)
        return StorageMetrics(
            self.storage_id, free_space=stats.f_bavail * stats.f_frsize,
            total_space=stats.f_bavail * stats.f_frsize + stats.f_blocks * stats.f_frsize)

    def get_tree(self, cached=False):
        tree = super().get_tree(cached=cached)
        # add stats
        tree.props[METRICS] = self.get_metrics()
        return tree

    def get_props(self, path):
        """Return event properties.
        :param path:
        :return: a dict with size, modified_date, version_id
        """
        fs_path = cc_path_to_fs(path, self.root)
        return get_eventprops_from_stat(fs_path)

    def get_tree_children(self, path):
        fs_path = cc_path_to_fs(path, self.root)
        fs_path = unicodedata.normalize('NFC', fs_path)

        for entry in os.scandir(fs_path):
            filename = unicodedata.normalize('NFC', entry.name)
            subpath = os.path.join(fs_path, filename)
            if not file_ignored(filename):
                try:
                    props = get_eventprops_from_dir_entry(entry)
                except OSError:
                    logger.info('Could not read props for file %s', subpath)
                    continue
                yield (filename, props)

    def update(self):
        """Do nothing in case of the filesystem."""
        pass

    def clear_model(self):
        """Do nothing in case of the filesystem."""

    def get_internal_model(self):
        """Do nothing as no model of filesystem."""

    def check_available(self):
        return

    def create_public_sharing_link(self, path):
        raise NotImplementedError

    def create_open_in_web_link(self, path):
        raise NotImplementedError


class FileSystemWatcher(FileSystemEventHandler):
    """The observer."""

    def __init__(self, storage):
        self.storage = storage

    def dispatch(self, event):
        # noinspection PyBroadException
        try:
            logger.debug(event)
            relative_path = os.path.relpath(event.src_path, self.storage.root)
            filename = os.path.basename(relative_path)
            if jars.utils.WriteToTempDirMixin.TEMPDIR in relative_path:
                self.on_from_temp(event)
            elif hasattr(event, 'dest_path') and \
                    file_ignored(os.path.basename(event.dest_path)):
                logger.info("File %s ignored", event.dest_path)
            elif file_ignored(relative_path) or \
                    file_ignored(filename) or event.src_path == self.storage.root:
                logger.info("File %s ignored", event.src_path)
            else:
                super().dispatch(event)
        except BaseException:
            logger.info("Error while handling a event", exc_info=True)

    def on_created(self, event):
        """Handle a create event."""
        cc_path = fs_to_cc_path(event.src_path, self.storage.root)

        event_props = get_eventprops_from_stat(event.src_path)
        self.storage.event_sink.storage_create(storage_id=self.storage.storage_id,
                                               path=cc_path,
                                               event_props=remove_private_props(event_props))

    def on_modified(self, event):
        """Handle a file modification event."""
        cc_path = fs_to_cc_path(event.src_path, self.storage.root)

        try:
            event_props = get_eventprops_from_stat(event.src_path)
        except FileNotFoundError:
            logger.info("can't stat file, ignoring event", exc_info=True)
            return
        self.storage.event_sink.storage_modify(storage_id=self.storage.storage_id,
                                               path=cc_path,
                                               event_props=remove_private_props(event_props))

    def on_deleted(self, event):
        """Handle a delete event."""
        cc_path = fs_to_cc_path(event.src_path, self.storage.root)

        self.storage.event_sink.storage_delete(storage_id=self.storage.storage_id,
                                               path=cc_path)

    def on_moved(self, event):
        """handle move events."""
        logger.debug("move handler '%s' -> '%s'", event.src_path, event.dest_path)
        cc_path_src = fs_to_cc_path(event.src_path, self.storage.root)
        cc_path_target = fs_to_cc_path(event.dest_path, self.storage.root)
        event_props = get_eventprops_from_stat(event.dest_path)

        self.storage.event_sink.storage_move(storage_id=self.storage.storage_id,
                                             source_path=cc_path_src,
                                             target_path=cc_path_target,
                                             event_props=remove_private_props(event_props))

    def on_from_temp(self, event):
        """Handle an event which has .crosscloud-tmp in the source path.

        Its a move event: write moved the file from the temp to its final destination.
        Ideally it would check if there was a file before and it was replaced,
        practically that is impossible and a storage_create will be called
        :param event: The watchdog event
        """
        if hasattr(event, 'dest_path'):

            cc_path_target = fs_to_cc_path(event.dest_path, self.storage.root)
            existed = False
            with self.storage.replace_operations_lock:
                if tuple(cc_path_target) in self.storage.replace_operations:
                    self.storage.replace_operations.remove(tuple(cc_path_target))
                    existed = True

            event_props = get_eventprops_from_stat(event.dest_path)
            if existed:
                self.storage.event_sink.storage_modify(storage_id=self.storage.storage_id,
                                                       path=cc_path_target,
                                                       event_props=event_props)

            else:
                self.storage.event_sink.storage_create(storage_id=self.storage.storage_id,
                                                       path=cc_path_target,
                                                       event_props=event_props)


def cc_path_to_fs(cc_path, root_path):
    """Convert a cc path list to the native path based on the root."""
    return os.path.join(root_path, os.path.sep.join(cc_path))


def fs_to_cc_path(fs_path, root_path):
    """Convert a fs path to a cc path."""
    relpath = os.path.relpath(fs_path, root_path)
    norm = unicodedata.normalize('NFC', relpath)
    cc_path = norm.split(os.path.sep)
    assert '..' not in cc_path, "%s contains '..'" % cc_path
    return cc_path


def get_eventprops_from_stat(path):
    """Returns a dict according to the spec from os.stat.
    TODO: rename to get_event_props_from_path
    """
    stat_result = os.stat(path)
    return _get_eventprops_from_stat(stat_result)


def _get_eventprops_from_stat(stat_result):
    """Returns a dict according to the spec from stat result.

    TODO: remove the _ from name once get_eventprops_from_stat has been renamed
    to get_event_props_from_path
    """
    event_props = {}
    if stat.S_ISDIR(stat_result.st_mode):
        event_props['version_id'] = 'is_dir'
        event_props['is_dir'] = True
    else:
        event_props['version_id'] = (stat_result.st_mtime_ns, stat_result.st_size)
        event_props['is_dir'] = False
    event_props['modified_date'] = datetime.datetime.fromtimestamp(
        stat_result.st_mtime_ns / 1e9)
    event_props['size'] = stat_result.st_size
    event_props['_inode'] = stat_result.st_ino
    event_props[jars.SHARED] = False
    return event_props


def get_eventprops_from_dir_entry(dir_entry):
    """Return a dict according to the spec from a scandir.DirEntry."""
    return _get_eventprops_from_stat(dir_entry.stat())


def file_ignored(file):
    """Check if a file is on the ignorance list.

    :param file: the path
    :return: True for an ignored list, False if not
    """
    for pattern in IGNORED_FILENAMES:
        if fnmatch.fnmatch(file, pattern):
            return True
    return False
