"""Contains the storage provider implementation for the Dropbox API v2[0] using longpolling.

The internal tree construction is done using 'path_lower' (see Dropbox Metadata) while
triggered events will use a path constructed using the "real" node name stored in
'_path_display_node'. To differentiate between the two "with_display" path should be set to True
if the actual representation is needed. For the events to contain the proper paths we use a
slightly modified TreeToSyncEngineAdapter called DropboxTreetoSyncEngineAdapter (see bottom of
the file).

Known Issues:
- Dropbox does not return meta-data for the root folder.
- Creating a "public_share" link will not trigger changes via long-polling. This results in
public_share changes to take up to around 2 minutes to be processed and visible locally.
- Fetching shared folder is currently limited to 1000 items and does not support pagination!
- Shared files are currently not supported!

[0]: https://www.dropbox.com/developers/documentation/http/overview
"""
import threading
import time
import functools
import datetime
import json
import logging
import hashlib
import copy
import contextlib
import requests

import bushn

import jars
from jars import VersionIdNotMatchingError, StorageError, \
    TreeToSyncEngineEngineAdapter, StorageMetrics, CURSOR
from jars.request_utils import error_mapper as default_error_mapper
from jars.streaming_utils import FragmentingChunker
from jars.utils import normalize_path
from jars.utils import filter_tree_by_path

# https://github.com/dropbox/dropbox-sdk-python/blob/master/dropbox/dropbox.py#L428
# here we extend the error map for a 409, which is used in case of version conflicts
ERROR_MAP = jars.request_utils.ERROR_MAP.copy()

# Client Specific errors should be handled individually!
# ERROR_MAP[409] = jars.VersionIdNotMatchingError

# Thrown when there are too many requests or write operations happening on
# a dropbox account.
ERROR_MAP[429] = jars.CurrentlyNotPossibleError

# Bad or expired token. This can happen if the access token is expired or
# if the access token has been revoked by Dropbox or the user. To fix
# this, you should re-authenticate the user.
ERROR_MAP[401] = jars.AccessDeniedError

# pylint: disable=invalid-name
error_mapper = functools.partial(default_error_mapper, error_map=ERROR_MAP)

ROOT_NODE_ID = 'cc:dropbox:root'
VERSION_ID_FIELD = 'content_hash'

SHARE_ID_INDEX_NAME = '_share_id_list'
PUBLIC_SHARE_INDEX_NAME = '_public_share_list'

logger = logging.getLogger(__name__)


def dropbox_client_error_mapper(fun):
    """A decorator which maps Dropbox Client errors (409) to Crosscloud specific errors.

    This handles ONLY Dropbox Client errors! Use this on top of the usual error
    mapper.
    """
    def new_fun(*args, **kwargs):
        """Function wrapper."""
        try:
            return fun(*args, **kwargs)
        except requests.exceptions.HTTPError as exception:
            try:
                error_dict = exception.response.json()
                reason = error_dict.get('error_summary', {"unkown/error"}).split("/")[1]
            except BaseException:
                # If any error happens during parsing - reraise the old one
                raise exception
            if exception.response.status_code == 409:
                if reason in ['no_write_permission']:
                    raise jars.AccessDeniedError(exception.response.text)
                elif reason in ['not_found']:
                    raise FileNotFoundError(exception.response.text)
                elif reason in ['malformed_path', 'disallowed_name', 'conflict', 'other']:
                    raise jars.InvalidOperationError(exception.response.text)
                # elif reason in ['insufficient_space']:
                #     raise jars.NoSpaceError(exception.response.text)
                elif reason in ['unkown']:
                    raise jars.SevereError(exception.response.text)
                else:
                    raise
            else:
                raise
    return new_fun


def _dropbox_item_to_crosscloud_props(item):
    """Map items from the dropbox to the crosscloud domain."""
    props = {}
    props['_id'] = item.get('id')
    props[jars.IS_DIR] = bool(item['.tag'] == 'folder')
    props[jars.SIZE] = item.get('size', 0)
    props[jars.MODIFIED_DATE] = datetime.datetime.strptime(
        item.get('server_modified', "1970-01-01T00:00:00Z"), "%Y-%m-%dT%H:%M:%SZ")

    if props[jars.IS_DIR]:
        props[jars.VERSION_ID] = jars.FOLDER_VERSION_ID
    else:
        props[jars.VERSION_ID] = item[VERSION_ID_FIELD]

    if 'path_display' in item:
        props['_path_display_node'] = item.get('path_display').split("/")[-1]
        props['_path_display'] = item.get('path_display')

    props[jars.SHARED] = item.get(jars.SHARED, props.get(jars.SHARED, False))
    logger.debug("      Item: %s", item)
    logger.debug("Properties: %s", props)
    return props


def _create_root_node():
    """Create and populate the properties of a new root node."""
    root = bushn.IndexingNode(name=None, indexes=['_id'])
    root.props['_id'] = ROOT_NODE_ID
    root.props[SHARE_ID_INDEX_NAME] = {}
    root.props[PUBLIC_SHARE_INDEX_NAME] = {}
    logger.debug("Created new root node!")
    return root


def _is_shared(props):
    """Check given a set of properties if an item is shared or not.

    A path is considered shared when it is either shared via a link or internally between
    dropbox users.
    """
    is_shared_item = props.get(jars.SHARE_ID, None)
    is_public_share = props.get(jars.PUBLIC_SHARE, None)

    is_shared_item = bool(is_shared_item and is_shared_item != bushn.DELETE)
    is_public_share = bool(is_public_share and is_public_share != bushn.DELETE)
    is_shared = bool(is_public_share or is_shared_item)

    return is_shared


def _update_share_properties(model):
    """Check which items in the tree have changed their state or might have been updated."""
    for node in model:
        if not node.parent:
            continue

        # Share
        if _is_shared(node.props) and not node.props[jars.SHARED]:
            node.props[jars.PUBLIC_SHARE] = node.props.get(
                jars.PUBLIC_SHARE,
                False)
            node.props[jars.SHARE_ID] = node.props.get(jars.SHARE_ID, False)
            node.props[jars.SHARED] = True
            logger.debug("'%s' is now shared!", node.path)
        # Update
        elif _is_shared(node.props) and node.props[jars.SHARED]:
            node.props[jars.PUBLIC_SHARE] = node.props.get(
                jars.PUBLIC_SHARE,
                False)
            node.props[jars.SHARE_ID] = node.props.get(jars.SHARE_ID, False)
            node.props[jars.SHARED] = True
            logger.debug("'%s' was updated and is still shared!", node.path)
        # Unshare
        elif not _is_shared(node.props) and node.props[jars.SHARED]:
            node.props[jars.PUBLIC_SHARE] = bushn.DELETE
            node.props[jars.SHARE_ID] = bushn.DELETE
            node.props[jars.SHARED] = False
            logger.debug("'%s' no longer shared.", node.path)
        else:
            logger.debug("'%s' did not change share state.", node.path)


def _readable_cursor(cursor):
    """Create human readable representation of a dropbox cursor."""
    return hashlib.sha1(cursor.encode('utf-8')).hexdigest()[0:10]


def as_crosscloud_path(path, normalize=False):
    """Transform (and opt. normalize) a given path from the Dropbox to the Crosscloud domain.

    :param path: the path to transform as a string e.g. /foobar/bar/baz
    :param normalize: whether to normalize the new path or not. default is True
    :return: a list containing the properly normalized path.
    """
    if path.startswith("/"):
        _path = path.split("/")[1:]
    else:
        _path = path.split("/")

    if normalize:
        _normalized_path = normalize_path(_path)
        logger.debug("'%s' -> %s.", path, _normalized_path)
        return _normalized_path

    logger.debug("'%s' -> %s.", path, _path)
    return _path


def as_dropbox_path(crosscloud_path):
    """Translate a given crosscloud path to the dropbox path."""
    if not len(crosscloud_path):
        # files/list_folder requires an empty string rather than '/'
        return ''

    if len(crosscloud_path) == 1 and (crosscloud_path[0] == '' or crosscloud_path[0] == '/'):
        # files/list_folder requires an empty string rather than '/'
        return ''

    return '/' + '/'.join(crosscloud_path)


class Dropbox(jars.OAuthBasicStorage):
    """Dropbox API v2 main class."""

    # pylint: disable=too-many-arguments,too-many-lines,too-many-public-methods

    storage_name = 'dropbox'
    storage_display_name = 'Dropbox'
    auth = [jars.BasicStorage.AUTH_OAUTH]

    # Credentials you get from registering a new application
    client_id = 'CLIENT_ID'
    client_secret = 'CLIENT_SECRET'
    redirect_uri = 'http://localhost:9324'

    authorization_base_url = "https://www.dropbox.com/oauth2/authorize"
    token_url = "https://api.dropboxapi.com/oauth2/token"
    base_url = 'https://api.dropboxapi.com/2/'

    scope = []
    grant_url_params = {}

    upload_fragment_size_min = 16 * 1024 * 1024 * 8
    upload_fragment_size = 8 * 1024 * 1024 * 8

    def __init__(self, event_sink, storage_id, storage_cred_reader,
                 storage_cache_dir=None, storage_cache_version=None,
                 storage_cred_writer=None):
        """Setup."""
        super().__init__(event_sink,
                         storage_id,
                         storage_cred_reader,
                         storage_cred_writer,
                         storage_cache_dir=storage_cache_dir,
                         storage_cache_version=storage_cache_version,
                         default_model=_create_root_node())
        self.event_poller = None
        self._failed_polling_requests = 0

    supports_serialization = True
    supports_open_in_web_link = True
    supports_sharing_link = False

    @classmethod
    def _oauth_get_unique_id(cls, oauth_session):
        """Return the unique account id for this dropbox account."""
        # https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
        return get_account_metadata(oauth_session)['account_id']

    @classmethod
    def wait_for_changes_once(cls, cursor, timeout=30):
        """Wait for changes (blocking) given a cursor and timeout.

        This calls the longpoll endpoint and will block for at least `timeout` seconds plus up
        to 90 seconds via Dropbox - added to prevent the thundering herd problem.
        """
        longpoll_endpoint = 'https://notify.dropboxapi.com/2/files/list_folder/longpoll'

        # This will block until timeout + x is reached.
        logger.debug("Waiting for changes... Cursor: '%s'", _readable_cursor(cursor))
        _start = time.time()
        response = requests.post(longpoll_endpoint,
                                 data=json.dumps({'cursor': cursor, 'timeout': timeout}),
                                 headers={'Content-Type': 'application/json'},
                                 timeout=30 + 90 + 10)
        response.raise_for_status()
        result = response.json()
        _stop = time.time()

        logger.debug("Waited for %3.2f...", (_stop - _start))

        if result.get('changes'):
            logger.debug("Found changes! Cursor '%s'.", _readable_cursor(cursor))
            logger.debug("Cursor: %s", _readable_cursor(cursor))
            return cursor, True, timeout, result.get('backoff', 0)

        logger.debug("No changes found! Cursor '%s'", _readable_cursor(cursor))
        return cursor, False, timeout, result.get('backoff', 0)

    def get_changes_since(self, current_cursor=None):
        """Return changes that happened since the given cursor.

        Returns all changes that happened since the given cursor. This is used to fetch
        the changes when the (long-)polling thread encounters the "changes" in the
        response.

        :param current_cursor: The cursor used as the "time-since" pointer/offset.
        :return:
        """
        list_folder_cont_url = "https://api.dropboxapi.com/2/files/list_folder/continue"

        if current_cursor:
            logger.debug("Fetching changes since %s", _readable_cursor(current_cursor))

        cursor = current_cursor
        while True:
            response = self.oauth_session.post(list_folder_cont_url,
                                               data=json.dumps({'cursor': cursor}),
                                               headers={'Content-Type': 'application/json'})
            result = response.json()
            changes = result.get('entries', [])
            logger.debug("%d Changes happened since cursor '%s'.",
                         len(changes), _readable_cursor(cursor))

            # Yield the cursor the result belongs to and the entry itself.
            for entry in changes:
                yield (cursor, entry)

            # No more results break from loop.
            if not result.get('has_more'):
                logger.debug("No more changes found. Returning.")
                break

            # More results. Adjust the cursor and repeat.
            cursor = result['cursor']

        # This will be the new cursor that should be written to the root model props.
        logger.debug("Cursor updated from '%s' -> '%s'", _readable_cursor(current_cursor),
                     _readable_cursor(result['cursor']))
        yield result['cursor'], None

    def get_latest_cursor(self, path='/', recursive=True):
        """Get the latest valid cursor (for the root folder) from the Dropbox API.

        :param path:
        :param recursive:
        :return:
        """
        _notify_url = "https://api.dropboxapi.com/2/files/list_folder/get_latest_cursor"
        headers = {'Content-Type': 'application/json'}
        data = json.dumps({'path': as_dropbox_path(path), 'recursive': recursive})
        response = self.oauth_session.post(_notify_url, data=data, headers=headers)
        _cursor = response.json()['cursor']
        logger.debug("Got current cursor '%s' for '%s'", _readable_cursor(_cursor), path)
        return _cursor

    def _update_shared_links(self, model):
        """Retrieve a list of all currently publicly shared links and updates the local index."""
        # https://www.dropbox.com/developers/documentation/http/documentation#sharing-list_shared_links
        # pylint: disable=too-many-locals
        logger.debug("*** Updating 'public_share's... ***")
        list_shared_links_endpoint = 'https://api.dropboxapi.com/2/sharing/list_shared_links'
        response = self.oauth_session.post(list_shared_links_endpoint,
                                           data=json.dumps({}),
                                           headers={'Content-Type': 'application/json'})
        response.raise_for_status()

        currently_shared_links = {}
        for link in response.json()['links']:
            logger.debug("Shared Link '%s' (%s): %s (%s)", link.get('path_lower'),
                         link.get('id'), link.get('url', "-"), link)

            path = as_crosscloud_path(link.get('path_lower'), normalize=True)
            currently_shared_links[link.get('url')] = (link.get('id'),
                                                       link.get('url'),
                                                       path)
        logger.debug("Current set contains %d shared links.", len(currently_shared_links))

        with model.lock:
            _public_share_index = model.props[PUBLIC_SHARE_INDEX_NAME]
            old_shared_links = set(_public_share_index.keys())

            # Since deleted nodes will not be present in the index the diff here will only contain
            # nodes we have to update.
            logger.debug("Adding newly shared links..")
            newly_shared_links = currently_shared_links.keys() - old_shared_links
            for url in newly_shared_links:
                _, link, path = currently_shared_links.get(url)
                assert link == url
                node = model.get_node(path)
                logger.debug("%s, %s, %s %s", url, path, node, node.props)
                node.props[jars.PUBLIC_SHARE] = True
                _public_share_index[url] = node
                assert url in _public_share_index

            logger.debug("Removing stale shared links..")
            no_longer_shared_links = old_shared_links - currently_shared_links.keys()
            for url in no_longer_shared_links:
                logger.debug("Remove LINK: %s", url)
                node = _public_share_index.pop(url)
                logger.debug("Remove LINK: %s, %s %s", url, node, node.props)
                node.props[jars.PUBLIC_SHARE] = bushn.DELETE
                assert url not in _public_share_index

            for url in currently_shared_links:
                _, url, path_lower = currently_shared_links[url]
                node = model.get_node(path_lower)
                assert node
                node.props[jars.PUBLIC_SHARE] = True
                _public_share_index[url] = node

    def _update_shared_items(self, model):
        """Fetch and update folders that are currently shared and mounted in the users Dropbox.

        This currently only handles folders and since there is currently no pagination happening
        on the folder endpoint only the first 1000 shared folder mountpoints will be checked!
        """
        # pylint: disable=too-many-locals
        logger.debug("*** Updating Shared Items ***")

        # TODO XXX: Pagination! Currently we only check the last 1000 shared folders.
        list_shared_folders_endpoint = 'https://api.dropboxapi.com/2/sharing/list_folders'
        response = self.oauth_session.post(list_shared_folders_endpoint,
                                           data=json.dumps({'limit': 1000}),
                                           headers={'Content-Type': 'application/json'})
        response.raise_for_status()

        currently_shared_folders = {}
        for folder in response.json()['entries']:
            if not folder.get('path_lower', None):
                logger.debug("Folder '%s' not mounted. Skipping!", folder.get('name'))
                continue

            logger.debug("Found shared Folder '%s' (%s): (%s)", folder.get('path_lower'),
                         folder.get('shared_folder_id'), folder)
            currently_shared_folders[folder.get('shared_folder_id')] = (
                folder.get('shared_folder_id'),
                as_crosscloud_path(folder.get('path_lower'), normalize=True),
                folder)
        logger.debug("Current set contains %d shared folders.", len(currently_shared_folders))

        with model.lock:
            shared_items = model.props[SHARE_ID_INDEX_NAME]
            old_shared_items = set(shared_items.keys())

            newly_shared_folders = currently_shared_folders.keys() - old_shared_items
            logger.debug("Adding newly shared %d folders", len(newly_shared_folders))
            for folder_id in newly_shared_folders:
                share_id, path, _ = currently_shared_folders.get(folder_id)
                node = model.get_node(path)
                node.props[jars.SHARE_ID] = share_id
                shared_items[share_id] = node
                assert share_id in shared_items
                logger.debug("Add %s %s", shared_items[share_id], shared_items[share_id].props)

            no_longer_shared_folders = old_shared_items - currently_shared_folders.keys()
            logger.debug("Removing %d un-mounted shared folders.", len(no_longer_shared_folders))
            for share_id in no_longer_shared_folders:
                node = shared_items.get(share_id)
                assert node
                try:
                    logger.debug("Remove %s, %s", share_id, node.props)
                    node.props[jars.SHARE_ID] = bushn.DELETE
                    del shared_items[share_id]
                except KeyError:
                    logger.debug("Already deleted.")
                assert share_id not in shared_items

            logger.debug("Handle nodes that are still in the index but might have changed.")
            for share_id, folder in currently_shared_folders.items():
                sid, path, _ = folder
                assert sid == share_id
                current_index_item = shared_items[sid]
                assert current_index_item
                node = model.get_node(path)
                assert node
                if current_index_item.path != node.path:
                    logger.debug("Item has been renamed.")
                    node.props[jars.SHARE_ID] = sid
                    shared_items[share_id] = node

    def _perform_long_polling(self, emit_events=False, cancel=False):
        """Start the long-polling chain.

        :param cancel: if set, after returning from longpoll nothing will be put into the model"""
        if jars.CURSOR not in self.model.props:
            logger.debug("Current model has no cursor property. Returning.")
            return

        with self.model.lock:
            current_cursor = self.model.props[jars.CURSOR]
            logger.debug("Using model cursor %s", _readable_cursor(current_cursor))

        try:
            logger.debug("*** *** Longpoll *** ***")
            cursor, has_changes, _, backoff = Dropbox.wait_for_changes_once(current_cursor)
            if cancel:
                logger.info('Cancelled long-polling within this thread(tid: %s), returning',
                            threading.get_ident())
                return

            logger.debug("Looks like we are online. Ensure that offline=False.")
            self.offline = False

            logger.debug("Resetting failed polling request counter.")
            self._failed_polling_requests = 0

            logger.debug("Setting cursor to %s.", _readable_cursor(cursor))

            if backoff > 0:
                logger.debug("Backing off for %d seconds.", backoff)
                time.sleep(backoff)

            # Apply the changeset if any, before updating the shared links section. This will
            # ensure that already deleted nodes will not be present in the index. However we
            # want ot check for updated shared links anyway.
            if has_changes:
                with self.model.lock:
                    self._update_model(cursor, emit_events)

            with contextlib.ExitStack() as stack:
                if emit_events:
                    stack.enter_context(DropboxTreeToSyncEngineAdapter(
                        node=self.model,
                        storage_id=self.storage_id,
                        sync_engine=self._event_sink))

                # 2. Perform the update of the shared links
                # In the worst case shared links will be updated every (30+(0-90)+10)s iff no
                # changes occur during the current call.
                logger.debug("Updating 'public_share' items.")
                self._update_shared_links(model=self.model)

                # 3. Perform the update of shared files and folders.
                # Handling this after applying the changeset ensures that we do not get files or
                # folders that are not yet existing locally.
                logger.debug("Updating 'share_id' items.")
                self._update_shared_items(model=self.model)

                # 4. Ensure node properties are set properly.
                logger.debug("Check and mark 'shared' items.")
                self._update_shared_items(model=self.model)

            if not has_changes:
                logger.debug("No changes occurred. Returning.")
                return

        except requests.ReadTimeout:
            # We do not want to go into offline mode immediately to prevent unnecessary hammering
            # of the storage API and triggering a full tree sync after going back online again.
            logger.info("Current long-polling request ran into a timeout.")
            self._failed_polling_requests += 1

            if self._failed_polling_requests >= 3:
                logger.warning("Long-polling failed three times. "
                               "Assuming we went offline.")
                self.offline = True
                self._failed_polling_requests = 0

            return

    def _prepare_changeset_for(self, cursor):

        changeset, final_cursor = [], cursor
        for current_cursor, change in self.get_changes_since(cursor):
            logger.debug("Change %s: %s", _readable_cursor(current_cursor), change)
            final_cursor = current_cursor

            if not change:
                logger.debug("No more changes.")
                break

            if change['.tag'] == 'deleted':
                with contextlib.suppress(KeyError):
                    # action, parent_id, name, props
                    node_path = as_crosscloud_path(change['path_lower'], normalize=True)
                    changeset.append(('DELETE', node_path, {}))
            else:
                # action, parent_id, name, props
                item = _dropbox_item_to_crosscloud_props(change)
                node_path = as_crosscloud_path(change['path_lower'], normalize=True)
                assert 'path_display' in change
                assert '_path_display_node' in item and '_path_display' in item
                changeset.append(('UPSERT', node_path, item))

        logger.debug("Gathered %d changes. Final cursor '%s'", len(changeset),
                     _readable_cursor(final_cursor))
        return changeset, final_cursor

    def _update_model(self, cursor, emit_events=False):
        logger.debug("*** Update Model ***")
        logger.debug("Updating Tree since Version '%s'", _readable_cursor(cursor))

        # Prepare a list of changes for the current cursor and store the last valid cursor.
        changeset, final_cursor = self._prepare_changeset_for(cursor)

        # Apply the changeset from above and update the model cursor using the `final_cursor`
        # from above.
        with contextlib.ExitStack() as stack:
            logger.debug("Trying to apply changeset with %d items.", len(changeset))
            if emit_events:
                stack.enter_context(DropboxTreeToSyncEngineAdapter(
                    node=self.model, storage_id=self.storage_id,
                    sync_engine=self._event_sink))

            for event, node_path, node_properties in changeset:
                if event == 'DELETE':
                    try:
                        logger.info("-> Deleting %s.", node_path)
                        node = self.model.get_node(node_path)
                        node.delete()
                    except KeyError:
                        logger.debug("-> '%s' already deleted?", node_path)
                else:
                    logger.info("-> Upserting %s.", node_path)

                    # If a node with the same _id exists this is a move?
                    node_id = node_properties.get('_id')
                    if node_id in self.model.index['_id']:
                        logger.debug("-> UPSERT: Node '%s' already exists!", node_id)
                        node = self.model.index['_id'].get(node_id)
                        node.parent = self.model.get_node_safe(node_path[:-1])
                        logger.debug("OLD: %s", node.props)
                        logger.debug("NEW: %s", node_properties)
                        node.props.update(node_properties)
                    else:
                        logger.debug("-> CREATE: Node '%s' not found in index. Creating!", node_id)
                        node = self.model.setdefault(node_path, node_properties)

            logger.debug("Applied changeset! Tree now has %d nodes.", len(self.model))
            self._print_shared_items_and_links()

        self.model.props[jars.CURSOR] = final_cursor
        logger.debug("Setting final cursor to %s", _readable_cursor(final_cursor))

        self.model.props[jars.METRICS].update(self.get_space_usage())
        logger.debug("Finished!")

    def update(self):
        """Update the internal model.

        Ensures the underlying internal representation of the tree is up-to-date. If we currently
        do not hold a cursor within the model's property dictionary create it by fetching the
        whole tree otherwise do a delta update using the current cursor.
        """
        with self.model.lock:
            if jars.CURSOR not in self.model.props:
                logger.debug("No cursor found in root properties. Fetching whole tree.")
                self.model = self.get_tree(cached=False, with_display_path=False, filtered=False)
            else:
                cursor = self.model.props[CURSOR]
                logger.debug("Performing delta update using cursor '%s'",
                             _readable_cursor(cursor))
                self._update_model(cursor, emit_events=False)

            # bushn.print_tree(self.model)
            logger.debug("Update finished!")

    def check_available(self):
        """See documentation of parent class."""
        super().check_available()

    @error_mapper
    @dropbox_client_error_mapper
    def open_read(self, path, expected_version_id=None):
        """See documentation of parent class."""
        parameters = {'path': as_dropbox_path(path), }
        headers = {'dropbox-api-arg': json.dumps(parameters),
                   'accept-encoding': None, }

        response = self.oauth_session.get('https://content.dropboxapi.com/2/files/download',
                                          headers=headers,
                                          stream=True)
        response.raise_for_status()

        result = json.loads(response.headers['dropbox-api-result'])

        if expected_version_id and result[VERSION_ID_FIELD] != expected_version_id:
            raise jars.VersionIdNotMatchingError(
                self.storage_id,
                path=path,
                version_b=expected_version_id,
                version_a=result[VERSION_ID_FIELD])

        return response.raw

    @error_mapper
    @dropbox_client_error_mapper
    def delete(self, path, original_version_id=None):
        """Check whether we are back online."""
        # https://www.dropbox.com/developers/documentation/http/documentation#files-delete
        logger.debug("Attempting to delete '%s' with '%s'", path, original_version_id)

        # If original_version_id is None this will return early.
        self._verify_version_id(path, original_version_id)
        logger.debug("Passed Version ID check")

        response = self.oauth_session.post('https://api.dropboxapi.com/2/files/delete',
                                           json={'path': as_dropbox_path(path)})
        response.raise_for_status()

    def _get_cached_tree(self, with_display_path):
        """Return cached version of the tree depending on 'with_display_path'.

        Helper function that can return a cached version of the tree in two forms either using
        built using '_path_display_node' (e.g. SyncEngine) or 'path_lower' (this module).
        :param with_display_path: Whether to use '_path_display_node' to build or not.
        :return: Copied version of the cached tree using either '_path_display_node' or
        'path_lower'.
        """
        with self.model.lock:

            if jars.CURSOR in self.model.props:
                logger.debug("Building 'cached' version %s of the tree. with_display_path=%s",
                             _readable_cursor(self.model.props[jars.CURSOR]),
                             with_display_path)
            else:
                logger.info("No cursor stored in root node!")

            adapter = DropboxTreeToSyncEngineAdapter(None, None, None)

            new_root = _create_root_node()
            for node in self.model:
                if node.parent is None:
                    new_root.props['_path_display_node'] = None
                    new_root.props.update(self.model.props)
                    continue

                if with_display_path:
                    node_path = adapter.transform_path(node)
                else:
                    node_path = node.path
                new_root.setdefault(node_path, node.props)

        logger.debug("Returning cached model with %d nodes; with_display_path=%s",
                     len(new_root),
                     with_display_path)
        return new_root

    def get_tree(self, cached=False, with_display_path=True, filtered=True):
        """Return the required representation of the internal tree.

        :param with_display_path: whether to use `_path_node_display` to construct the tree.
        :param cached: whether or not to return a cached version of the tree.
        :return: the root index node
        """
        # pylint: disable=arguments-differ,too-many-locals,too-many-statements

        list_folder_endpoint = 'https://api.dropboxapi.com/2/files/list_folder'
        list_folder_continue_endpoint = 'https://api.dropboxapi.com/2/files/list_folder/continue'

        if cached:
            if filtered:
                cached_tree = self._get_cached_tree(with_display_path)
                return filter_tree_by_path(cached_tree, self.filter_tree)
            else:
                return copy.deepcopy(self.model)

        # Create root node containing storage metrics.
        root = _create_root_node()
        root.props[jars.METRICS] = self.get_space_usage()

        headers = {'Content-Type': 'application/json'}
        response = self.oauth_session.post(list_folder_endpoint,
                                           data=json.dumps({'path': as_dropbox_path('/'),
                                                            'recursive': True}),
                                           headers=headers)

        response.raise_for_status()
        result = response.json()
        has_more = result.get('has_more', False)

        # Get, transform and add items from the current page.
        for item in result.get('entries', None):
            props = _dropbox_item_to_crosscloud_props(item)
            path = as_crosscloud_path(item['path_lower'], normalize=True)
            if with_display_path:
                path = as_crosscloud_path(item['path_display'], normalize=False)

            logger.debug("Adding node '%s'", path)
            root.setdefault(path, props)  # get_node_safe(path).props.update(props)
            node = root.get_node(path)
            logger.debug("Node '%s' (%s) Props: %s", node.name, node, node.props.items())

        root.props[jars.CURSOR] = result['cursor']

        if has_more:
            logger.debug("fetch more")

        while has_more:
            _current_cursor, _current_page = result.get('cursor', None), 1
            logger.debug(_current_cursor)

            response = self.oauth_session.post(list_folder_continue_endpoint,
                                               data=json.dumps({'cursor': _current_cursor}),
                                               headers=headers)
            response.raise_for_status()
            result = response.json()
            logger.debug("Cursor: %s, Page: %s", _readable_cursor(_current_cursor), _current_page)

            # Add items from the current page to the tree.
            for item in result.get('entries', None):
                props = _dropbox_item_to_crosscloud_props(item)
                path = as_crosscloud_path(item['path_lower'], normalize=True)
                if with_display_path:
                    path = as_crosscloud_path(item['path_display'], normalize=False)
                logger.debug(path)
                root.setdefault(path, props)  # get_node_safe(path).props.update(props)

            has_more = result.get('has_more', False)
            if has_more:
                logger.debug("Dropbox has more items.")
                logger.debug("Current page is %s. New Cursor '%s'", _current_page,
                             _readable_cursor(_current_cursor))
                _current_page = _current_page + 1
                _current_cursor = result.get('cursor', None)
            else:
                # TODO: Somehow this does not work with _current_cursor?
                root.props[jars.CURSOR] = result.get('cursor', None)
                logger.debug("No more cursors; Finished fetching entries.")
                _current_cursor = None

        logger.debug("No more cursors; Finished fetching entries. Cursor '%s'",
                     _readable_cursor(root.props[jars.CURSOR]))

        logger.debug("Updating 'public_share' items.")
        self._update_shared_links(model=root)
        logger.debug("Updating 'share_id' items.")
        self._update_shared_items(model=root)
        logger.debug("Check and mark 'shared' items.")
        self._update_shared_items(model=root)

        if filtered:
            return filter_tree_by_path(root, self.filter_tree)
        return root

    @error_mapper
    @dropbox_client_error_mapper
    def get_tree_children(self, path):
        """Get the contents of the given path directly from the Dropbox API.

        This will call-out to the Dropbox API and only fetch the contents of a given path
        without its subfolders.
        :param path: The crosscloud path to lookup
        :return: yields tuples containing the node name and its properties.
        """
        # https://www.dropbox.com/developers/documentation/http/documentation#files-list_folder

        logger.debug("Path: %s", path)

        data = json.dumps({"path": as_dropbox_path(path),
                           "recursive": False,
                           "include_media_info": False,
                           "include_deleted": False,
                           "include_has_explicit_shared_members": False})
        headers = {'Content-Type': 'application/json'}
        response = self.oauth_session.post("https://api.dropboxapi.com/2/files/list_folder",
                                           data=data,
                                           headers=headers)

        if response.status_code == 409 and 'not_found' in response.json().get('error_summary'):
            logger.debug("Path %s (%s) not found!", path, as_dropbox_path(path))
            raise FileNotFoundError

        response.raise_for_status()

        for entry in response.json().get('entries', []):
            node_properties = _dropbox_item_to_crosscloud_props(entry)
            yield (entry['name'], node_properties)

    @error_mapper
    @dropbox_client_error_mapper
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """See documentation of parent class."""
        logger.debug("Trying to move %s (%s) -> %s (%s)", source, expected_source_vid,
                     target, expected_target_vid)

        if expected_source_vid:
            self._verify_version_id(source, expected_source_vid)

        if expected_target_vid:
            self._verify_version_id(target, expected_target_vid)

        was_replaced = False
        try:
            logger.debug("Checking whether the target %s exists.", target)
            self._get_meta_data(target)
            logger.debug("Target exists. Trying to delete it.")
            self.delete(target)
            was_replaced = True
        except FileNotFoundError:
            logger.debug("No conflicting target found!")

        if was_replaced:
            logger.debug("Target was replaced!")

        parameters = {
            'from_path': as_dropbox_path(source),
            'to_path': as_dropbox_path(target),
            'allow_shared_folder': False,
            'autorename': False,
        }
        response = self.oauth_session.post('https://api.dropboxapi.com/2/files/move',
                                           json=parameters)
        response.raise_for_status()

        metadata = _dropbox_item_to_crosscloud_props(self._get_meta_data(target))

        logger.debug("Moved %s (%s) -> %s (%s)", source, expected_source_vid, target,
                     expected_target_vid)
        return metadata[jars.VERSION_ID]

    @error_mapper
    @dropbox_client_error_mapper
    def make_dir(self, path):
        """See documentation of parent class."""
        # https://www.dropbox.com/developers/documentation/http/documentation#files-create_folder
        create_folder_endpoint = 'https://api.dropboxapi.com/2/files/create_folder'
        parameters = {
            'path': as_dropbox_path(path),
            'autorename': False,
        }
        try:
            response = self.oauth_session.post(create_folder_endpoint, json=parameters)
            response.raise_for_status()
            logger.debug("Created folder '%s'.", path)
        except requests.exceptions.HTTPError as err:
            error_summary = response.json().get('error_summary', "")
            if err.response.status_code != 409 and "path/conflict/folder" not in error_summary:
                logger.error("Unable to create folder '%s'", as_dropbox_path(path))
                raise err

        metadata = self._get_meta_data(path)
        logger.debug("Folder created! Metadata for '%s': %s", path, metadata)

        return jars.FOLDER_VERSION_ID

    @error_mapper
    @dropbox_client_error_mapper
    def write(self, path, file_obj, original_version_id=None, size=0):
        """Upload a given file object to the given path.

        It looks like if a file is written to a non-existing parent path this path
        structure will be automatically created.
        :param path:
        :param file_obj:
        :param original_version_id:
        :param size:
        :return:
        """
        DROPBOX_UPLOAD_ENDPOINT = 'https://content.dropboxapi.com/2/files/upload'
        parameters = {
            'path': as_dropbox_path(path),
            'autorename': False,
            'mute': False,
            'mode': 'overwrite'
        }

        if original_version_id:
            self._verify_version_id(path, original_version_id)
            # We've verified the content_hash. Thus the revision should not have changed!?
            original_revision = self._get_meta_data(path)['rev']
            parameters['mode'] = {'.tag': 'update', 'update': original_revision}
            logger.debug("Original Version ID specified. Updating API Parameters.")

        headers = {'Dropbox-API-Arg': json.dumps(parameters),
                   'Content-Type': 'application/octet-stream'}

        # If we exceed the maximum upload size a large file upload is triggered.
        if size > self.upload_fragment_size_min:
            logger.debug("Handling file upload with large-sized file.")
            return self._upload_large(file_obj, size, parameters)

        logger.debug("Handling file upload with normal-sized file.")
        response = self.oauth_session.post(
            DROPBOX_UPLOAD_ENDPOINT, data=file_obj.read(), headers=headers)
        response.raise_for_status()

        _ = self._get_meta_data(path)

        return response.json()[VERSION_ID_FIELD]

    def _upload_large(self, file_obj, size, headers):
        """Upload a large file using upload sessions.

        :param file_obj: the file object to upload
        :param size: the objects total size
        :param headers: the dropbox args which specify the path and upload method
        :return: the files revision id
        """
        # https://www.dropbox.com/developers/documentation/http/documentation#files-upload_session-start

        # Create Session and Upload first Fragment
        session_start_header = {'Dropbox-API-Arg': json.dumps({'close': False}),
                                'Content-Type': 'application/octet-stream'}

        fragmenter = FragmentingChunker(file_obj,
                                        chunk_size=self.upload_fragment_size,
                                        total_size=size)

        initial_chunk = next(iter(fragmenter))
        session_response = self.oauth_session.post(
            'https://content.dropboxapi.com/2/files/upload_session/start',
            headers=session_start_header,
            data=initial_chunk)
        session_response.raise_for_status()

        session_id = session_response.json()['session_id']

        logger.debug("Upload Session ID is '%s'.", session_id)

        # Append data to the session
        # post each fragment with the specified offset
        offset = fragmenter.fragment_begin
        while not fragmenter.exhausted:
            logger.debug("Session ID '%s', Offset %d", session_id, offset)
            session_append_header = {
                'Dropbox-API-Arg': json.dumps(
                    {
                        'cursor': {
                            'session_id': session_id,
                            'offset': offset
                        },
                        'close': False
                    }),
                'Content-Type': 'application/octet-stream'}
            fragment_response = self.oauth_session.post(
                'https://content.dropboxapi.com/2/files/upload_session/append_v2',
                data=fragmenter,
                headers=session_append_header)

            logger.debug(fragment_response.headers)
            logger.debug(fragment_response.content)
            fragment_response.raise_for_status()
            offset = fragmenter.fragment_begin

        # Finish the upload
        # by setting the path and closing the session
        session_finish_header = {
            'Dropbox-API-Arg': json.dumps(
                {
                    'cursor': {
                        'session_id': session_id,
                        'offset': fragmenter.total_read
                    },
                    'commit': headers,
                }),
            'Content-Type': 'application/octet-stream'}
        logger.debug("Session ID '%s', Offset %d", session_id, offset)
        response = self.oauth_session.post(
            'https://content.dropboxapi.com/2/files/upload_session/finish',
            headers=session_finish_header)
        response.raise_for_status()
        return response.json()[VERSION_ID_FIELD]

    def create_open_in_web_link(self, path):
        """Return a direct link to the dropbox item."""
        if path == []:
            return "https://www.dropbox.com/home"

        if not path:
            raise StorageError(storage_id=self.storage_id, origin_error=None)

        try:
            db_path = as_dropbox_path(path)
            self.model.get_node(path[:-1])
        except Exception as err:
            raise StorageError(storage_id=self.storage_id, origin_error=err)

        return "{}{}".format("https://www.dropbox.com/home", db_path)

    @error_mapper
    @dropbox_client_error_mapper
    def create_public_sharing_link(self, path):
        """Create a public sharing link."""
        raise NotImplementedError

    def start_events(self):
        """Start the event handling."""
        def set_offline(value):
            """Set current state to offline."""
            self.offline = value

        if (self.event_poller and not self.event_poller.is_alive()) or not self.event_poller:
            self.event_poller = jars.PollingScheduler(interval=1.0,
                                                      target=self._perform_long_polling,
                                                      target_kwargs={'emit_events': True},
                                                      offline_callback=set_offline)
            logger.debug("Resetting failed polling request counter.")
            self._failed_polling_requests = 0
            self.event_poller.start()

    def stop_events(self, join=False):
        """Stop event poller."""
        if self.event_poller is not None:
            # we are not emiting events and cancel the next operation
            self.event_poller.target_kwargs = {'emit_events': False, 'cancel': True}
            self.event_poller.offline_callback = lambda x: x
            # join does not matter here, there won't be any events emitted any longer
            self.event_poller.stop(join=False)
            self.event_poller = None

    def clear_model(self):
        """Clear internal model and setup new root node."""
        self.model = _create_root_node()
        logger.debug("*** Cleared Model! ***")

    def get_internal_model(self):
        """Return the internal model."""
        return self.model

    @error_mapper
    @dropbox_client_error_mapper
    def get_shared_folders(self):
        """Return the list of shared folders and their members."""
        # https://www.dropbox.com/developers/documentation/http/documentation#sharing-list_folder_members/continue
        # https://www.dropbox.com/developers/documentation/http/documentation#sharing-list_file_members/continue

        shared_items = self.model.props[SHARE_ID_INDEX_NAME]
        logger.debug("%s shared items in index. Fetching members.", len(shared_items))

        def fetch_shared_item_members(node, limit=1000):
            """Fetch shared item members for node.

            Yields 'UserMembershipInfo' by calling the "list_folder_members" and (if necessary)
            "list_folder_members/continue" until all members have been retrieved.

            :param node: the node/folder the members lookup should be performed on.
            :param limit: the number of folders per page (1000 is the dropbox limit/default).
            :return: yields "UserMembershipInfo" dictionaries.

            Example:
            >>> fetch_shared_item_members(node)
            { "access_type": { ".tag": "owner" },
            "user": { "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc" },
            "permissions": [],
            "is_inherited": false }
            """
            share_id = node.props['share_id']

            if node.props[jars.IS_DIR]:
                endpoint = "https://api.dropboxapi.com/2/sharing/list_folder_members"
                payload = {"shared_folder_id": share_id, "actions": [], "limit": limit}
                logger.debug("Fetching members for shared folder '%s'...", share_id)
            else:
                endpoint = "https://api.dropboxapi.com/2/sharing/list_file_members"
                payload = {"file": share_id, "include_inherited": False, "limit": 100}
                logger.debug("Fetching members for shared file '%s'...", share_id)

            # Send initial request. This might result into paging if 'cursor' is present.
            response = self.oauth_session.post(endpoint, json=payload)
            response.raise_for_status()

            for user in response.json().get("users", []):
                yield user

            cursor = response.json().get('cursor', None)

            while cursor:
                logger.debug("Found cursor! Retrieving next page with cursor '%s'", cursor)
                _endpoint = endpoint + "/continue"
                response = self.oauth_session.post(_endpoint, json={"cursor": cursor})
                response.raise_for_status()

                for user in response.json().get("users", []):
                    yield user

                cursor = response.json().get('cursor', None)
                if cursor:
                    logger.debug("Fetching next page with cursor '%s'", cursor)

            logger.debug("Exhausted member list for item %s", share_id)

        # Create and populate the list of shared folders here.
        shared_item_objs = []
        for shared_item_id in set(shared_items.keys()):
            logger.debug("Getting members for shared item id '%s'.", shared_item_id)
            node = shared_items.get(shared_item_id)
            item_id = node.props['share_id']
            assert node

            # TODO: XXX: Handles only Dropbox users!
            # This implementation currently only handles sharing between Dropbox users.
            # Invitees and Groups are not resolved or added to the list of members.
            member_ids = set()

            # Extract the relevant 'account_id' from every 'UserMembershipInfo' returned.
            for member in fetch_shared_item_members(node):
                member_unique_id = member.get('user', {'account_id': None}).get('account_id', None)
                if member_unique_id:
                    logger.debug("Account '%s' is member of '%s'.", member_unique_id, item_id)
                    member_ids.add(member_unique_id)
                else:
                    logger.debug("No account id was found in the user entry!")

            # Prepare and add the SharedFolder object.
            sfo = jars.SharedFolder(path=node.path,
                                    share_id=item_id,
                                    sp_user_ids=set(member_ids))
            shared_item_objs.append(sfo)
            logger.debug(sfo)

        # Add shared public links
        _owner = self._oauth_get_unique_id(self.oauth_session)
        shared_links = self.model.props[PUBLIC_SHARE_INDEX_NAME]
        logger.debug("%s shared links in index.", len(shared_links))
        for url in shared_links:
            node = shared_links.get(url)
            sfo = jars.SharedFolder(path=node.path,
                                    share_id=url,
                                    sp_user_ids=[_owner])
            shared_item_objs.append(sfo)
            logger.debug(sfo)

        logger.debug("Collected %d shared folder objects", len(shared_item_objs))
        return shared_item_objs

    def __repr__(self):
        """Return object repr. description."""
        return '<Dropbox storage_id="{}">'.format(self.storage_id)

    @error_mapper
    @dropbox_client_error_mapper
    def get_space_usage(self):
        """Return current Dropbox account usage.

        Returns a tuple containing the used and allocated (= total available) space for either an
        individual (default) or a team.
        :return: Updated StorageMetrics object with the current metrics for the storage.
        """
        # https://www.dropbox.com/developers/documentation/http/documentation#users-get_space_usage

        response = self.oauth_session.post('https://api.dropboxapi.com/2/users/get_space_usage')
        response.raise_for_status()
        result = response.json()

        used_space = result['used']
        allocated_space = result['allocation']['allocated']
        free_space = (allocated_space - used_space)

        metrics = StorageMetrics(self.storage_id,
                                 free_space=free_space,
                                 total_space=allocated_space)

        logger.debug("Fetched StorageMetrics %s", metrics)
        return metrics

    @error_mapper
    @dropbox_client_error_mapper
    def _get_current_account(self):
        """Fetch information associated with the currently paired account.

        StorageMetrics will be set during initial update or get_tree and/or after applying a
        changeset (see _update_model).
        :return:
        """
        # https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
        response = self.oauth_session.post(
            'https://api.dropboxapi.com/2/users/get_current_account')
        response.raise_for_status()
        return response.json()

    def _verify_version_id(self, path, version_id):
        """Verify that the item under `path` has the version `version_id`.

        Helper function to verify a given version_id with actual version id retrieved via the API.
        If the returned meta data describes a folder or no version id was given we return
        immediately. Otherwise we ensure that both the .tag and content_hash are present and
        compare them to their expected values.

        :param path: The Crosscloud path which will be passed to `self._get_meta_data`.
        :param version_id: The version_id to be checked against.
        :return:
        """
        if not version_id:
            logger.debug("No version_id given. Returning.")
            return

        # This will through a LookupError (HTTP 409) if a non-existing path was given.
        metadata = self._get_meta_data(path)

        # Version checks are not defined for folders. If the returned metadata
        # describes a folder we return.
        if 'folder' in metadata['.tag']:
            metadata[VERSION_ID_FIELD] = jars.FOLDER_VERSION_ID
            logger.debug("Object '%s' appears to be a folder.", path)
            logger.debug("Setting '%s' to '%s'.", VERSION_ID_FIELD, 'is_dir')

        # Ensure that we have a content_hash to compare. In the case of a folder this simply is
        # "is_dir". If the given hash and the one retrieved from the API do not match raise
        # a VersionNotMatchingError.
        assert VERSION_ID_FIELD in metadata

        if metadata[VERSION_ID_FIELD] != version_id:
            raise VersionIdNotMatchingError(storage_id=self.storage_id)

    @dropbox_client_error_mapper
    def _get_meta_data(self, path):
        """Get metadata for the given dropbox path."""
        metadata_endpoint = 'https://api.dropboxapi.com/2/files/get_metadata'
        parameters = {
            'path': as_dropbox_path(path),
            'include_media_info': False,
            'include_deleted': False,
            'include_has_explicit_shared_members': False,
        }
        headers = {'Content-Type': 'application/json'}
        data = json.dumps(parameters)
        response = self.oauth_session.post(metadata_endpoint, data=data, headers=headers)
        response.raise_for_status()
        return json.loads(response.text)

    def _print_shared_items_and_links(self):
        """Print shared items and links in the current internal model."""
        with self.model.lock:
            shared_items = self.model.props[SHARE_ID_INDEX_NAME]
            shared_links = self.model.props[PUBLIC_SHARE_INDEX_NAME]

            logger.debug("Printing shared folders.")
            for key in shared_items.keys():
                node = shared_items.get(key)
                logger.debug("->(%s) %s %s %s %s", key, node.name, node.path, node.parent,
                             node.props)

            logger.debug("Printing shared links.")
            for key in shared_links.keys():
                node = shared_links.get(key)
                logger.debug("URL ->(%s) %s %s %s %s", key, node.name, node.path, node.parent,
                             node.props)

    def _print_nodes_in_index(self, index, model=None):
        """Print the nodes contained within the given index."""
        if not model:
            model = self.model

        with model.lock:
            logger.debug("Printing '%s' index.", index)
            for key in model.index[index].keys():
                node = model.index[index].get(key)
                logger.debug("->(%s) %s %s %s %s", key, node.name, node.path, node.parent,
                             node.props)

    def serialize(self):
        """Serialize model."""
        self.model.props[jars.MODEL_VERSION_KEY] = '2'
        super(Dropbox, self).serialize()

    def create_user_name(self):
        """Return a username for Dropbox.

        In this case the username will be 'display_name', obtained using
        https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
        """
        metadata = get_account_metadata(self.oauth_session)
        try:
            return metadata['name']["display_name"]
        except KeyError:
            logger.debug('No display_name field found, setting up email as username.')
            return metadata['email']


def get_account_metadata(oauth_session):
    """Get the current account metadata and return a json."""
    response = oauth_session.post(
            'https://api.dropboxapi.com/2/users/get_current_account')
    response.raise_for_status()
    return response.json()


class DropboxTreeToSyncEngineAdapter(TreeToSyncEngineEngineAdapter):
    """TreeToSyncEngineAdapter using '_path_display_node' instead of 'path'.

    Custom TreeToSyncEngineEngineAdapter to use transformed paths (based on
    'path_display'/'_path_display_node') instead of the 'path_lower' based paths used by the
    internal tree.
    """

    def transform_path(self, node):
        """Return path using '_path_display_node' for a given `node`.

        Returns the transformed path of a node by iterating of all nodes parents and collecting
        '_path_display_node'.

        :param node: The base node to be used as the "endpoint" of the path.
        :return:
        """
        logger.debug("Transform path for %s ", node.name)
        if node.parent is None:
            return []

        # logger.debug("Transform path for %s (%s)", node.name, node.props['_path_display_node'])

        path = []
        for n in node.iter_up:
            elem = n.props.get('_path_display_node', None)
            if elem:
                # logger.debug("+- %s (%s)", n.name, n.props['_path_display_node'])
                path.append(elem)

            if n.parent is None:
                # logger.debug("+- %s is None. Hit root, returning path.", n)
                break

        transformed_path = list(reversed(path))
        logger.debug("'%s' (display=%s) with '%s' has %s", node.name,
                     node.props['_path_display_node'],
                     node.path, transformed_path)
        return copy.copy(transformed_path)


# register this module at the storages
jars.registered_storages.append(Dropbox)
