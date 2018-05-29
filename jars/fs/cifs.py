"""
Windows only implementation for CIFS.This is based on the standard filesystem,
but it needs a model as well to be able to send deletes after a storages has come
online after beeing offline again.
"""
import json
import logging
import threading
import time
import ctypes

import win32netcon
import bushn

import jars
import jars.fs
import jars.utils

from . import Filesystem
from jars import winapi

logger = logging.getLogger(__name__)


def net_use(credentials):
    """ tries to conenct to a windows share """
    resource = winapi.NETRESOURCE()
    resource.lpLocalName = None  # no drive letter assignment
    resource.lpRemoteName = credentials['unc_path']
    resource.lpProvider = None

    # do net use magic
    value = winapi.WNetAddConnection2(
        ctypes.byref(resource), credentials.get('password'), credentials.get('username'),
        win32netcon.CONNECT_TEMPORARY)

    logger.debug("WNetAddConnection2: %x", value)


class CifsIsOnlineCheck(threading.Thread):
    """ Helper thread trying to connect to a share until doomsday """

    def __init__(self, online_callback, credentials):
        super().__init__()
        self._credentials = credentials
        self._online_callback = online_callback

    def run(self):
        offline = True
        while offline:
            try:
                logger.debug("Check if online")
                time.sleep(1)
                net_use(self._credentials)
                offline = False
                logger.debug("Now online")
            except WindowsError as error:
                if error.winerror == winapi.ERROR_BAD_NETPATH:
                    logger.debug("Not online")
                else:
                    raise

        self._online_callback()


class ModelUpdatingEventSink:
    """ This just updates the model according to the events """

    def __init__(self, root_node, next_event_sync):
        self.root_node = root_node
        self.next_event_sync = next_event_sync

    def storage_create(self, storage_id, path, event_props):
        """ Creation of a file or dir """
        self.next_event_sync.storage_create(storage_id=storage_id, path=path,
                                            event_props=event_props)
        node = self.root_node.get_node_safe(path)
        node.props.update(event_props)

    def storage_delete(self, storage_id, path):
        """ Deletion of a file or dir """
        self.next_event_sync.storage_delete(storage_id=storage_id, path=path)
        try:
            node = self.root_node.get_node(path)
            node.delete()
        except KeyError:
            logger.warning('Cannot delete non existing ')

    def storage_modify(self, storage_id, path, event_props):
        """ Modify of a file or dir """
        self.next_event_sync.storage_modify(storage_id=storage_id, path=path,
                                            event_props=event_props)
        node = self.root_node.get_node_safe(path)
        node.props.update(event_props)

    def update_tree(self, new_model, storage_id):
        """ compares the new model with the exiting one and throws events in case of
        changes """
        for node in new_model:
            if node.parent is None:
                continue

            try:
                old_node = self.root_node.get_node(node.path)
                if old_node.props['version_id'] != node.props['version_id']:
                    logger.debug('different %s!=%s', old_node.props, node.props)
                    self.next_event_sync.storage_modify(storage_id=storage_id,
                                                        path=node.path,
                                                        event_props=node.props)

            except KeyError:
                self.next_event_sync.storage_create(storage_id=storage_id,
                                                    path=node.path,
                                                    event_props=node.props)

        # find deletions
        for deleted_node in set(self.root_node) - set(new_model):
            self.next_event_sync.storage_delete(storage_id=storage_id,
                                                path=deleted_node.path)

        self.root_node = new_model

    def __getattr__(self, item):
        """ redirect all other function to """
        return getattr(self.next_event_sync, item)


class CifsFileSystem(Filesystem):
    """ Implementation of CIFS based on windows api calls
    """

    storage_name = 'cifs'
    storage_display_name = 'Windows Share'

    def create_open_in_web_link(self, path):
        raise NotImplementedError

    def create_public_sharing_link(self, path):
        raise NotImplementedError

    def check_available(self):
        logger.debug("Checking if CIFS share is available.")
        try:
            net_use(self._credentials)
        except WindowsError as err:
            logger.debug('Cant access windows share at the moment', exc_info=True)
            raise jars.StorageOfflineError(self.storage_id, origin_error=err)

    auth = [jars.BasicStorage.AUTH_CREDENTIALS]

    def __init__(self, event_sink, storage_id, storage_cache_dir,
                 storage_cred_reader, storage_cred_writer, polling_interval=30):
        # pylint: disable=too-many-arguments,unused-argument

        # getting credentials from store
        self._credentials = json.loads(storage_cred_reader())

        super(CifsFileSystem, self).__init__(self._credentials['unc_path'],
                                             event_sink,
                                             storage_id)

        try:
            net_use(self._credentials)
        except WindowsError:
            self._offline = False
            logger.debug('Cant access windows share at the moment', exc_info=True)

        self.storage_cache_dir = storage_cache_dir
        self._event_sink = ModelUpdatingEventSink(
            next_event_sync=self._event_sink,
            root_node=jars.load_model(storage_cache_dir,
                                      bushn.Node(None)))

    def update(self):
        self._event_sink.root_node = self.get_tree()

    def clear_model(self):
        self._event_sink.root_node = None

    def get_tree(self, cached=False):
        if cached:
            logger.debug('returning copy of %s', self._event_sink.root_node)
            return jars.utils.filter_tree_by_path(self._event_sink.root_node,
                                                  self.filter_tree)
        return super().get_tree(cached=cached)

    def start_events(self):
        try:
            super().start_events()
        except FileNotFoundError as error:
            if error.winerror == winapi.ERROR_BAD_NETPATH:
                self.start_online_checker()
            else:
                raise

    def start_online_checker(self):
        """ starts a thread which checks if the cifs share is online
        """
        if self.watch_thread:
            self.watch_thread.close()

        CifsIsOnlineCheck(
            self._online_callback,
            self._credentials).start()

    def watcher_error_callback(self, exception):
        if exception.winerror == winapi.ERROR_NETNAME_DELETED:
            self.offline = True
            self.event_sink.storage_offline(self.storage_id)
            self.start_online_checker()
        else:
            super(CifsFileSystem, self).watcher_error_callback(exception)

    def _online_callback(self):
        logger.info('went online again')

        # start the watcher again
        if self.watch_thread:
            self.watch_thread.close()

        self.watch_thread = None
        self.start_events()

        # now fetch the tree and fire a event for every element
        self._event_sink.update_tree(self.get_tree(), self.storage_id)

        # send sync engine that we are online again
        self.offline = False

    def serialize(self):
        jars.save_model(self._event_sink.root_node, self.storage_cache_dir)

    supports_serialization = True

    @classmethod
    def authenticate(cls, url, username, password, verify, force):
        # pylint: disable=too-many-function-args,unused-argument,arguments-differ
        # pylint: disable=too-many-arguments
        if not username:
            username = None
        if not password:
            password = None
        credentials = {'unc_path': url, 'username': username,
                       'password': password}
        net_use(credentials)

        return [], json.dumps(credentials), url


jars.registered_storages.append(CifsFileSystem)
