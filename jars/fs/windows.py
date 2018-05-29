"""
Base class for the file system under Windows operating systems
"""
import contextlib
import ctypes
import ctypes.wintypes
import logging
import os
import struct
import threading
import time

import queue
import uuid

from jars import VersionIdNotMatchingError, CurrentlyNotPossibleError, \
    StorageMetrics
from jars.fs.filesystem import cc_path_to_fs, fs_to_cc_path, FilesystemBasic, \
    get_eventprops_from_stat, file_ignored
from jars import winapi, remove_private_props
from jars.utils import WriteToTempDirMixin

logger = logging.getLogger(__name__)

EVENT_STRING_MAPPING = {
    winapi.FILE_ACTION_ADDED: 'FILE_ACTION_ADDED',
    winapi.FILE_ACTION_MODIFIED: 'FILE_ACTION_MODIFIED',
    winapi.FILE_ACTION_OVERFLOW: 'FILE_ACTION_OVERFLOW',
    winapi.FILE_ACTION_REMOVED: 'FILE_ACTION_REMOVED',
    winapi.FILE_ACTION_RENAMED_NEW_NAME: 'FILE_ACTION_RENAMED_NEW_NAME',
    winapi.FILE_ACTION_RENAMED_OLD_NAME: 'FILE_ACTION_RENAMED_OLD_NAME'
}


class WindowsFileReader:
    """A file like object for windows. This is exists to enable posix like behavior for opening
    files in read mode.

    The basic problem is that if a file is opened with ``open(filename, 'rb')`` other processes
    cannot delete or rename them any longer. The first solution is to open the file with
    ``FILE_SHARE_DELETE``, but this solution only marks the file as deleted and prevents to create
    files with the same name in the same directory.

    The solution is to create a hardlink to the file in an other before opening it. It is needed to
    create the file in an other directory to have the ability to delete the directory where it is
    originated in. Before the hardlink gets created it is necessary to check if the file can be
    accessed(`move`_), otherwise one won't be able to remove the hardlink or read from it. The link
    then will be opened with ``FILE_FLAG_DELETE_ON_CLOSE``, which ensures the hardlink is removed
    after accessing it.

    .. _move: https://stackoverflow.com/questions/1951791#answer-28983991
    """

    def __init__(self, fname, tmpdir,
                 shared_mode_flags=winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE |
                 winapi.FILE_SHARE_DELETE,
                 flags_and_attributes=winapi.FILE_ATTRIBUTE_NORMAL |
                 winapi.FILE_FLAG_DELETE_ON_CLOSE):

        # check if the file can be opened
        os.rename(fname,
                  fname)

        # the filename for the hardlink
        open_fname = os.path.join(tmpdir,
                                  '~read-{}-{}.tmp'.format(os.path.basename(fname), uuid.uuid4()))

        logging.debug('Creating hardlink %s->%s', fname, open_fname)
        winapi.CreateHardLinkW(
            open_fname,  # lpFileName
            fname,  # lpExistingFileName
            None  # lpSecurityAttributes
        )

        # now open the file
        self.handle = winapi.CreateFileW(
            open_fname,  # lpFileName
            winapi.FILE_READ_DATA,  # dwDesiredAccess
            shared_mode_flags,  # dwShareMode
            None,  # lpSecurityAttributes
            winapi.OPEN_EXISTING,  # dwCreationDisposition
            flags_and_attributes,  # dwFlagsAndAttributes
            None  # hTemplateFile
        )

        self.fname = fname
        self.pos = 0

    def _read(self, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.wintypes.DWORD()
        winapi.ReadFile(self.handle,
                        ctypes.byref(buffer),
                        size,
                        ctypes.byref(bytes_read),
                        None)
        self.pos += bytes_read.value
        return buffer.raw[:bytes_read.value]

    def read(self, size=None, chunk_size=16 * 1024):
        """ reads from the file """
        if size is not None:
            return self._read(size)
        else:
            col = []
            while True:
                buf = self._read(chunk_size)
                if not buf:
                    return b''.join(col)
                col.append(buf)

    def close(self):
        """ closes the windows file handle """
        logger.debug("Closing file")
        # only call this if we had a handle, in case of a exception in the ctor there
        # is no handle
        if hasattr(self, 'handle'):
            winapi.CloseHandle(self.handle)
            self.handle = winapi.INVALID_HANDLE_VALUE

    def tell(self):
        """ returns the current stream position (bytes read)"""
        return self.pos

    def __del__(self):
        # only close the file, if it was not already closed
        if getattr(self, 'handle', winapi.INVALID_HANDLE_VALUE) != winapi.INVALID_HANDLE_VALUE:
            self.close()


def convert_long_path(path):
    """ uses GetLongPathNameW to convert a filename with ~ 8.3 substitution to real paths
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa364980(v=vs.85).aspx
    """
    if '~' not in path:
        return path

    buffer_length = 512
    result = ''
    while True:
        buffer = ctypes.create_unicode_buffer(buffer_length)
        ret_code = winapi.GetLongPathName(path, buffer, len(buffer))
        if ret_code < buffer_length:
            result = buffer.value
            break
        buffer_length = ret_code + 1
    return result


class WatchedDirectory(object):
    """ This class represents the directory watched with ReadDirectoryChangesW"""

    # pylint: disable=too-many-branches, too-many-nested-blocks,
    # pylint: disable=too-many-instance-attributes,too-many-arguments
    # pylint: disable=no-self-use
    def __init__(self, callback, path, flags, buffer_size=64 * 1024, recursive=True):
        self.path = path
        self.flags = flags
        self.callback = callback
        self.recursive = recursive
        self.handle = None
        self.error = None
        self.handle = winapi.CreateFileW(
            path,
            winapi.FILE_LIST_DIRECTORY,
            winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
            None,
            winapi.OPEN_EXISTING,
            winapi.FILE_FLAG_BACKUP_SEMANTICS | winapi.FILE_FLAG_OVERLAPPED,
            None)
        self.result = ctypes.create_string_buffer(buffer_size)
        self.overlapped = winapi.OVERLAPPED()
        self.ready = threading.Event()

    def __del__(self):
        self.close()

    def close(self):
        """ closes the handle to the directory """
        if self.handle is not None:
            winapi.CloseHandle(self.handle)
            self.handle = None

    def post(self):
        """ retrigger a read """
        overlapped = self.overlapped
        overlapped.Internal = 0
        overlapped.InternalHigh = 0
        overlapped.Offset = 0
        overlapped.OffsetHigh = 0
        overlapped.Pointer = 0
        overlapped.hEvent = 0
        try:
            logger.debug('Calling ReadDirectoryChangesW for directory %s; '
                         'recursive: %s', self.path, self.recursive)
            winapi.ReadDirectoryChangesW(self.handle,
                                         ctypes.byref(self.result), len(self.result),
                                         self.recursive, self.flags, None,
                                         overlapped, None)
        except WindowsError as error:
            logger.exception('Error calling ReadDirectoryChangesW')
            self.error = error
            self.close()

    def complete(self, nbytes):
        """ when a read is complete this function is called """
        # pylint: disable=no-self-use
        if nbytes == 0:
            self.callback(None, 0)
        else:
            res = self.result.raw[:nbytes]
            for (name, action) in self._extract_change_info(res):
                if self.callback:
                    try:
                        self.callback(os.path.join(self.path, name), action)
                    except FileNotFoundError:
                        logger.debug('file not found (nothing unusual)')
                    except BaseException:
                        logger.exception('callback failed for some reason')

    def _extract_change_info(self, buffer):
        """Extract the information out of a FILE_NOTIFY_INFORMATION structure."""
        pos = 0
        while pos < len(buffer):
            jump, action, namelen = struct.unpack("iii", buffer[pos:pos + 12])

            name = buffer[pos + 12:pos + 12 + namelen].decode("utf16")
            yield (name, action)
            if not jump:
                break
            pos += jump


class WatchThread(threading.Thread):
    """Thread for watching filesystem changes."""

    # pylint: disable=too-many-branches, too-many-nested-blocks,
    # pylint: disable=too-many-instance-attributes,too-many-arguments
    # pylint: disable=no-self-use
    def __init__(self, error_callback=lambda x: None, buffer_size=64 * 1024):
        super(WatchThread, self).__init__(daemon=True)
        self.closed = False
        self.watched_directories = {}
        self.ready = threading.Event()
        self._iocp = None
        self._new_watches = queue.Queue()
        self._buffer_size = buffer_size
        self._error_callback = error_callback

    def close(self):
        """ shuts down everything """
        if not self.closed:
            self.closed = True
            if self._iocp:
                with contextlib.suppress(OSError):
                    winapi.PostQueuedCompletionStatus(self._iocp, 0, 1, None)

    def add_watcher(self, callback, path, recursive):
        """ add a watcher to a certain directory """
        if os.path.isfile(path):
            path = os.path.dirname(path)
        watched_dirs = []
        for watch_dir in self._get_watched_dirs(callback, path, recursive):
            self.attach_watched_directory(watch_dir)
            watched_dirs.append(watch_dir)
        return watched_dirs

    def del_watcher(self, path):
        """ deletes a watcher to a certain path """
        watch_dir = self.watched_directories.pop(hash(path))
        watch_dir.callback = None
        watch_dir.close()

    def _get_watched_dirs(self, callback, path, recursive):
        flags = winapi.FILE_NOTIFY_CHANGE_FILE_NAME | \
            winapi.FILE_NOTIFY_CHANGE_DIR_NAME | \
            winapi.FILE_NOTIFY_CHANGE_ATTRIBUTES | \
            winapi.FILE_NOTIFY_CHANGE_SIZE | \
            winapi.FILE_NOTIFY_CHANGE_LAST_WRITE | \
            winapi.FILE_NOTIFY_CHANGE_SECURITY | \
            winapi.FILE_NOTIFY_CHANGE_LAST_ACCESS | \
            winapi.FILE_NOTIFY_CHANGE_CREATION
        return [WatchedDirectory(
            callback=callback, path=path, flags=flags,
            buffer_size=self._buffer_size,
            recursive=recursive)]

    def run(self):
        try:
            self._iocp = winapi.CreateIoCompletionPort(winapi.INVALID_HANDLE_VALUE, None,
                                                       0, 1)
            self.ready.set()
            nbytes = ctypes.wintypes.DWORD()
            iocpkey = ctypes.wintypes.DWORD()
            overlapped = winapi.OVERLAPPED()
            while not self.closed:
                try:
                    winapi.GetQueuedCompletionStatus(self._iocp,
                                                     ctypes.byref(nbytes),
                                                     ctypes.byref(iocpkey),
                                                     ctypes.byref(overlapped),
                                                     -1)
                except WindowsError as ex:
                    # offline detection would go here
                    self._error_callback(ex)
                else:
                    if iocpkey.value > 1:
                        # pylint: disable=used-before-assignment
                        try:
                            watch_dir = self.watched_directories[iocpkey.value]
                        except KeyError:
                            pass
                        else:
                            watch_dir.complete(nbytes.value)
                            watch_dir.post()
                    elif not self.closed:
                        try:
                            while True:
                                watch_dir = self._new_watches.get_nowait()
                                if watch_dir.handle is not None:
                                    winapi.CreateIoCompletionPort(watch_dir.handle,
                                                                  self._iocp,
                                                                  hash(watch_dir), 0)
                                    watch_dir.post()
                                watch_dir.ready.set()
                        except queue.Empty:
                            pass
        finally:
            self.ready.set()
            for watch_dir in self.watched_directories.values():
                watch_dir.close()
            if self._iocp:
                winapi.CloseHandle(self._iocp)

    def attach_watched_directory(self, watch_dir):
        """ attach the watched dir """

        self.watched_directories[hash(watch_dir)] = watch_dir
        self._new_watches.put(watch_dir)
        winapi.PostQueuedCompletionStatus(self._iocp, 0, 1, None)
        watch_dir.ready.wait()


class WindowsFileBaseSystem(FilesystemBasic):
    """ This implementation has some special features regarding windows:
    * non-exclusive opening of files
    * hiding all files starting with a .
    """

    def __init__(self, root, event_sink, storage_id):
        # this is attached to enable long paths
        if not root.startswith('\\\\'):
            root = '\\\\?\\' + convert_long_path(root)

        # create tempdir and hide it
        self.tempdir = os.path.join(root, WriteToTempDirMixin.TEMPDIR)
        if not os.path.exists(self.tempdir):
            logger.info("Temporary directory does not exist creating it.")
            os.mkdir(self.tempdir)
            logger.info("Created temporary directory at '%s'.", self.tempdir)
        else:
            logger.info("Using existing temporary directory at '%s'.", self.tempdir)

        winapi.SetFileAttributes(self.tempdir, winapi.FILE_ATTRIBUTE_HIDDEN)

        super().__init__(root, event_sink, storage_id)
        self.watch_thread = None
        logger.debug('instantiated WindowsFileBaseSystem with root "%s"', root)
        self.filter_tree.on_create.connect(self._filter_tree_create)
        self.filter_tree.on_delete.connect(self._filter_tree_deleted)

        # used for rename detection
        self.old_path = None

    def _filter_tree_create(self, node):
        # pass
        if self.watch_thread is not None and self.watch_thread.is_alive():
            fs_path = cc_path_to_fs(node.path, self.root)
            logger.debug('Adding watcher for "%s"', fs_path)
            # self.watch_thread.add_watcher(self.watcher_callback, fs_path,
            # recursive=True)
            # self.generate_events_for_tree(fs_path)

    def _filter_tree_deleted(self, node):
        pass
        # if self.watch_thread is not None and self.watch_thread.is_alive():
        #     fs_path = cc_path_to_fs(node.path, self.root)
        #     logger.debug('Removing watcher for "%s"', fs_path)
        #     with contextlib.suppress(KeyError):
        #         self.watch_thread.del_watcher(fs_path)

    def watcher_error_callback(self, exception):
        """ Called if the watcher failes
        """
        # pylint: disable=no-self-use
        logger.exception("Error while calling: %s", exception)

    def watcher_callback(self, path, action):
        """ callback for the filewatcher  """
        # need to test and refactor this anyway
        # pylint: disable=too-many-nested-blocks
        logger.debug('Raw windows event: %s, %s', path, action)

        # happens when the handler is closed
        if not path:
            return

        path = convert_long_path(path)
        logger.debug(path)

        relative_path = os.path.relpath(path, self.root)
        filename = os.path.basename(relative_path)
        if file_ignored(os.path.basename(path)) \
                or file_ignored(filename) or file_ignored(relative_path):
            logger.info("File %s ignored", relative_path)
            return

        if action == 0:
            logger.debug("stopping")
            return

        event_props = None
        with contextlib.suppress(FileNotFoundError):
            event_props = get_eventprops_from_stat(path)

        cc_path = fs_to_cc_path(path, self.root)
        if event_props is not None:
            if action == winapi.FILE_ACTION_ADDED:
                self._event_sink.storage_create(storage_id=self.storage_id,
                                                path=cc_path,
                                                event_props=remove_private_props(event_props))
                # this might trigger events double, but the syncengine knows how to
                # handle that
                if os.path.isdir(path):
                    self.generate_events_for_tree(path)

            elif action == winapi.FILE_ACTION_MODIFIED:
                self._event_sink.storage_modify(storage_id=self.storage_id,
                                                path=cc_path,
                                                event_props=remove_private_props(event_props))
            elif action == winapi.FILE_ACTION_RENAMED_NEW_NAME:
                self.rename_folder(cc_path=cc_path, event_props=event_props)

        if action == winapi.FILE_ACTION_REMOVED:
            self._event_sink.storage_delete(
                storage_id=self.storage_id, path=cc_path)
        elif action == winapi.FILE_ACTION_RENAMED_OLD_NAME:
            self.old_path = cc_path
        elif action == winapi.FILE_ACTION_OVERFLOW:
            logger.error('Well, this is an overflow message')

    def rename_folder(self, cc_path, event_props):
        """ helper function to rename sp folder """
        if self.old_path:
            logger.debug('Move from %s -> %s', self.old_path, cc_path)
            self._event_sink.storage_move(
                storage_id=self.storage_id, source_path=self.old_path,
                target_path=cc_path, event_props=remove_private_props(event_props))
            self.old_path = None
        else:
            logger.critical('Was not able to reconstruct filename')

    def generate_events_for_tree(self, path):
        """ walks down a a directory and emits create events for all files """
        logger.debug('walking down the line for %s', path)
        for dirpath, dirnames, filenames in os.walk(path):
            for entry in dirnames + filenames:
                try:
                    path = os.path.join(dirpath, entry)
                    logger.debug('triggering artificial event for %s', path)
                    event_props = get_eventprops_from_stat(path)
                    cc_path = fs_to_cc_path(path, self.root)
                    self._event_sink.storage_create(
                        storage_id=self.storage_id,
                        path=cc_path,
                        event_props=remove_private_props(event_props))
                except OSError:
                    logger.debug('Cannot stat %s', path, exc_info=True)

    def start_events(self):
        """ For windows we are not going to use the watchdog class"""

        if self.watch_thread is None or \
                (self.watch_thread is not None and not self.watch_thread.is_alive()):
            self.watch_thread = WatchThread(error_callback=self.watcher_error_callback)
            self.watch_thread.start()
            time.sleep(0.1)

            logger.debug('Enabling watchers')
            for filter_node in self.filter_tree:
                # add a flat watcher for every filter node with children to observe the
                # files in the same directory and a recursive one to all children if none
                # to watch them recursively

                recursive = not bool(filter_node.children)
                path = cc_path_to_fs(filter_node.path, self.root)
                logger.debug('Adding watcher for "%s", recursive: %s', path, recursive)
                self.watch_thread.add_watcher(
                    self.watcher_callback,
                    path=path,
                    recursive=recursive)

    def stop_events(self, join=False):
        if self.watch_thread is None:
            return

        self.watch_thread.close()

        if join:
            self.watch_thread.join()

            # super().stop_events(join)
            # self.explorer_notifier.stop()

    def _hide_if_starts_with_dot(self, path):
        logger.debug('Hiding ? %s', path)
        if path and path[-1][0] == '.':
            logger.debug('Hiding %s', path)
            with contextlib.suppress(PermissionError):
                winapi.SetFileAttributes(cc_path_to_fs(path, self.root),
                                         winapi.FILE_ATTRIBUTE_HIDDEN)

    def open_read(self, path, expected_version_id=None):
        fs_path = cc_path_to_fs(path, self.root)
        # self.explorer_notifier.in_queue.put(fs_path)
        props = get_eventprops_from_stat(fs_path)
        if expected_version_id is not None and props['version_id'] != expected_version_id:
            raise VersionIdNotMatchingError(storage_id=self.storage_id,
                                            path=path,
                                            version_b=expected_version_id,
                                            version_a=props['version_id'])

        try:
            file_obj = WindowsFileReader(fs_path, self.tempdir)
            return file_obj
        except WindowsError as error:
            # if error code is 32 there is a sharing violation -> currently not possible
            if error.winerror == 32:
                raise CurrentlyNotPossibleError(self.storage_id, origin_error=error)
            else:
                raise

    def _write(self, path, file_obj, original_version_id=None):
        res = super()._write(path, file_obj, original_version_id)
        return res

    def make_dir(self, path):
        vid = super().make_dir(path)
        self._hide_if_starts_with_dot(path)
        return vid

    def delete(self, path, original_version_id):
        try:
            return super().delete(path, original_version_id)
        except WindowsError as error:
            # if error code is 32 there is a sharing violation -> currently not possible
            if error.winerror == 32:
                raise CurrentlyNotPossibleError(self.storage_id, origin_error=error)
            else:
                raise

    def get_metrics(self):
        free_bytes, total_bytes = get_free_total_space(self.root)

        return StorageMetrics(self.storage_id, free_space=free_bytes,
                              total_space=total_bytes)

    def write(self, path, file_obj, original_version_id=None, size=0):
        raise NotImplementedError


def get_free_total_space(path):
    """ returns the free space for the path, using GetDiskFreeSpaceExW """
    free_bytes = ctypes.wintypes.ULARGE_INTEGER()
    total_bytes = ctypes.wintypes.ULARGE_INTEGER()

    winapi.GetDiskFreeSpaceEx(path,
                              ctypes.byref(free_bytes),
                              ctypes.byref(total_bytes),
                              None)

    return free_bytes.value, total_bytes.value


def main():
    """ this main function is to test the windows watcher """

    def watcher_callback(path, action):
        """ watcher callback for experiments """
        logger.debug(path, EVENT_STRING_MAPPING[action])
        if os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                for entry in dirnames + filenames:
                    path = os.path.join(dirpath, entry)
                    with contextlib.suppress(OSError):
                        event_props = get_eventprops_from_stat(path)
                        logger.debug(path, event_props)

    logging.basicConfig(level=logging.DEBUG)

    watch_thread = WatchThread()
    watch_thread.start()
    time.sleep(0.1)

    watch_thread.add_watcher(watcher_callback, r'c:\tmp', recursive=True)
    watch_thread.join()


if __name__ == '__main__':
    main()
