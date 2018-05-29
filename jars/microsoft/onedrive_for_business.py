"""This module implements a storage which can talk to OneDrive for business."""

import os
import contextlib
import logging
import copy

import dateutil
import requests

import bushn
import jars
from jars.microsoft import microsoft_graph
from jars.microsoft.onedrive import error_mapper
# Note this is a special Errormap which raises VersionIdNotMatchingError for 409

logger = logging.getLogger(__name__)


def to_path(cc_path):
    """Return a version of the path that the graph api can deal with."""
    if cc_path == []:
        return None
    else:
        return '/'.join(cc_path)


def is_dir(item_meta):
    """Determine if an item is a directory based on the meta data provided."""
    return 'folder' in item_meta


def get_mod_date(item_meta):
    """Extract the datetime of the last modification from the item_meta."""
    return dateutil.parser.parse(item_meta['lastModifiedDateTime'])


def get_size(item_meta):
    """Exctract the size from an item_meta."""
    return item_meta.get('size', 0)


UPLOAD_FRAGMENT_SIZE_MIN = 8 * 1024
"""file size, used to decide if large file upload method should be used or just `PUT`"""

DELTA_URL = '_delta_url'
"""Key used in node props to stash the delta_token if a DeltaIterator, has been used previously.
"""


class OneDriveBusiness(jars.BasicStorage):
    """Handle a microsoft onedrive for business storage."""

    API_CLASS = microsoft_graph.MicrosoftGraphApi
    URL_BUILDER_CLASS = microsoft_graph.UrlBuilder
    supports_serialization = True

    storage_name = "onedrivebusiness"
    storage_display_name = 'OneDrive for Business'

    base_url = 'https://graph.microsoft.com'

    auth = [jars.BasicStorage.AUTH_OAUTH]

    delta_item_fields = ['deleted',
                         'id',
                         'parentReference',
                         'eTag',
                         'lastModifiedDateTime',
                         'name',
                         'folder']
    skip_tmp_file = True
    is_shared = False

    def __init__(self, *args, storage_cred_writer=None, storage_cred_reader=None,
                 polling_interval=10, group_id=None, api=None, **kwargs):
        """Initalise OneDriveBusiness by using a provided api or initializing a new one.

        This is the first step towards refactoring the api out of the storage.
        """
        # setup BasicStorage
        super().__init__(*args, **kwargs)

        # setup the api
        if api is not None:
            self.api = api
        else:
            self.api = self.API_CLASS(storage_cred_writer=storage_cred_writer,
                                      storage_cred_reader=storage_cred_reader,
                                      event_sink=None, storage_id=None)

        # setup url_builder
        self.urls = self.URL_BUILDER_CLASS(self.base_url)

        # set_up event_poller
        self.event_poller = self._init_poller(polling_interval)
        self.polling_interval = polling_interval

        # save group_id if this instance deals with a group.
        self.group_id = group_id

    def check_available(self):
        """Check if the api is authenticated."""
        try:
            _ = self.api.get('drive')
        except requests.exceptions.HTTPError as exception:
            if exception.response.status_code == 401:
                raise jars.AuthenticationError(storage_id=self.storage_id,
                                               origin_error=exception)
            else:
                raise jars.StorageOfflineError(storage_id=self.storage_id,
                                               origin_error=exception)
        except BaseException as error:
            raise jars.StorageOfflineError(storage_id=self.storage_id,
                                           origin_error=error)

    def list_avaliable_groups(self):
        """Return the groups of which the user is a member."""
        url = self.urls.build('groups')
        response = self.api.get(url).json()
        for meta in response['value']:
            group_id = meta['id']
            url = self.urls.build('groups/{id}/owners'.format(id=group_id))
            response = self.api.get(url)
            owner_ids = [user['id'] for user in response.json()['value']]
            meta['owners'] = owner_ids
            if self.api.drive_id in owner_ids \
                    and self._group_is_online(group_id=group_id):
                yield meta

    def _group_is_online(self, group_id):
        """Determine if the endpoints of a share can be reaced.

        Background is the afer adding a owner to a share it takes about half a day until
        the endpoints are actualy usable.
        """

        root_url = self.urls.root_info(group_id=group_id)
        response = self.api.get(root_url, status_check=None)
        return response.status_code == 200

    @classmethod
    def grant_url(cls):
        """Pass the grant_url on from the api."""
        return cls.API_CLASS.grant_url()

    @classmethod
    def authenticate(cls, *args, **kwargs):
        """Pass authenticate from the api."""
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = 'true'
        auth = cls.API_CLASS.authenticate(*args, **kwargs)
        del os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']
        return auth

    def clear_model(self):
        """Empty the model. Used in testing."""
        self.model = bushn.IndexingNode(None, indexes=['_id'])

    # pylint: disable=arguments-differ
    def get_tree(self, cached=False, filtered=True):
        """Fetch and return the full tree and its metadata."""
        if cached:
            model = self.model
        else:
            model = self.get_update(self.create_new_model())

        with self.model.lock:
            if filtered:
                tree = jars.utils.filter_tree_by_path(model, self.filter_tree)
            else:
                tree = copy.deepcopy(self.model)
        return tree
    # pylint: enable=arguments-differ

    @error_mapper
    def get_tree_children(self, path):
        """Get the childen of the provided path."""
        # TODO: pageinate
        if path == []:
            # root
            url = self.urls.children(group_id=self.group_id)
        else:
            meta = self._get_meta(path)
            url = self.urls.children(path, parent_meta=meta, group_id=self.group_id)

        children = self.api.get(url=url).json()['value']

        # return a list of tuples of name and props.
        return [(child_meta['name'], self._cc_props(child_meta))
                for child_meta in children]

    def start_events(self):
        """Start the event poller."""
        if self.event_poller.is_alive():
            pass
        try:
            self.event_poller.start()
        except RuntimeError:
            self.event_poller = self._init_poller(self.polling_interval)
            self.event_poller.start()

    def _init_poller(self, polling_interval):
        """Initialize the event poller by setting it's callbacks."""
        def set_offline(value):
            """Set the offline state."""
            self.offline = value

        def update_callback():
            """Get a full update of the tree and save it to the internal model."""
            self.model = self.get_update(self.model, emit_events=True)

        # creating poller getting events from the storage
        return jars.PollingScheduler(
            polling_interval,
            target=update_callback,
            offline_callback=set_offline)

    def stop_events(self, join=False):
        """Stop the event_poller."""
        self.event_poller.stop()

    def update(self):
        """Update the interal model of this storage."""
        if self.model.props == {}:
            self.model = self.create_new_model()
        self.model = self.get_update(self.model)

    @error_mapper
    def create_new_model(self, name=None):
        """Create a new root node, by calling the api and setting the props accordingly."""
        model = bushn.IndexingNode(name=name, indexes=['_id'])

        # set the metrics
        url = self.urls.drive_info(group_id=self.group_id)
        drive_info = self.api.get(url, params={'select': 'quota'}).json()
        model.props['metrics'] = jars.StorageMetrics(
            self.storage_id,
            free_space=drive_info['quota']['remaining'],
            total_space=drive_info['quota']['total'])

        # set the id of the root node
        url = self.urls.root_info(self.group_id)
        root_info = self.api.get(url, params={'select': 'id'}).json()
        root_id = root_info['id']
        model.props['_id'] = root_id
        return model

    @error_mapper
    def get_update(self, model=None, emit_events=False):
        """Return an updated version of the provided model.

        If model is set to None, a brand new model is created.

        :param model: model to update. defaults to None
        :param emit_events: wether to trigger events when merging.
        """
        self._update_node(node=model, emit_events=emit_events)
        return model

    def _cc_props(self, item_meta):
        """Convert an item_meta to cc props."""
        props = {jars.VERSION_ID: self._version_id_from_meta(item_meta),
                 '_id': item_meta['id'],
                 jars.IS_DIR: is_dir(item_meta),
                 jars.MODIFIED_DATE: get_mod_date(item_meta),
                 jars.SIZE: get_size(item_meta),
                 jars.SHARED: self.is_shared
                 }
        return props

    def _update_node(self, node, emit_events=False):
        """Get a delta url from the node and merge the changes returned into the model."""
        delta_url = node.props.get(DELTA_URL, None) or self.urls.delta(group_id=self.group_id)

        delta_iterator = microsoft_graph.OneDriveIterator(url=delta_url,
                                                          api=self.api)

        merge_set = []
        for item in delta_iterator:
            if item['id'] == node.props['_id'] or 'root' in item:
                logger.debug('ignoring root')
                continue

            if self.skip_tmp_file and item.get('name', '').startswith('~tmp'):
                # Note: ~tmp files are created when an upload is canceled.
                # TODO: is there a good way to remove these?
                logger.debug('skipping temp file: %s', item['name'])
                continue

            merge_set.append(self._convert_to_merge_tuple(item))

        self._add_merge_set_to_model(
            merge_set=merge_set, node=node, emit_events=emit_events)
        # stash the delta_url for next time.
        node.props[DELTA_URL] = delta_iterator.last_response['@odata.deltaLink']

    def _add_merge_set_to_model(self, merge_set, node, emit_events=False):
        """Add a set of merges to a model and emit events if needed.

        The merge is done with the TreeToSyncEngineEngineAdapter, in order to have the appropriate
        events triggered if emit_events is set.
        """
        with contextlib.ExitStack() as stack:
            if emit_events:
                stack.enter_context(jars.TreeToSyncEngineEngineAdapter(
                    node=node, storage_id=self.storage_id,
                    sync_engine=self._event_sink))

            left_overs = node.add_merge_set_with_id(merge_set, '_id')
            if left_overs:
                logger.critical('Left overs from delta: %s', left_overs)

    def _convert_to_merge_tuple(self, item_meta):
        """Convert an item meta to a tuple which can be fed to _add_merge_set_to_model."""
        try:
            parent_id = item_meta['parentReference']['id']
        except KeyError:
            parent_id = self.group_id
        props = {}
        action = 'UPSERT'

        if 'deleted' in item_meta:
            # logger.debug('*** delete for %s', item_meta)
            action = 'DELETE'
            props = {'_id': item_meta['id']}
        else:
            # logger.debug('+++ delta for %s', item_meta['name'])
            props = self._cc_props(item_meta=item_meta)

        return bushn.NodeChange(action=action,
                                parent_id=parent_id,
                                name=item_meta.get('name'),
                                props=props)

    @error_mapper
    def make_dir(self, path):
        """Create a directory at the provided path on the remote."""
        # return if root
        if path == []:
            return
        list(self._iter_dir_safe(path))
        return 'is_dir'

    def _iter_dir_safe(self, path):
        """Do the same as iter_path but create folders if not avaliable.

        Note: all items of the path will be created, so if a path to a file is needed, the
        filename should be excluded from the path.
        """
        item_meta_iter = self._iter_path(path)
        dir_meta = next(item_meta_iter)
        yield dir_meta

        if path == []:
            # path is root, for which meta has been yielded.
            raise StopIteration

        # how far does iter_path get?
        for elem in path:
            try:
                dir_meta = next(item_meta_iter)
            except (StopIteration, FileNotFoundError):
                # The rest must be created
                dir_create_url = self.urls.new_dir(parent_dir_meta=dir_meta,
                                                   group_id=self.group_id)
                json_data = {"name": elem,
                             "folder": {}}
                dir_meta = self.api.post(dir_create_url, json=json_data).json()
            yield dir_meta

    def _iter_path(self, path):
        """Iterate over the path returning the item meta dict if successfull.

        XXX: this requires to many requests. Try to reduce
        :raises FileNotFoundError: when an element of the path cannot be found on the server.
        """
        root_url = self.urls.root_info(self.group_id)
        root_meta = self.api.get(url=root_url).json()

        # yield the root, so list(iter_path(path)) can't be empty
        yield root_meta
        # yield the meta of the rest of the path.

        item_meta = root_meta
        for idx, elem in enumerate(path):
            child_url = self.urls.children(parent_meta=item_meta,
                                           path=path[:idx],
                                           group_id=self.group_id)
            children_meta = self.api.get(url=child_url).json()

            matching_children = [child for child in children_meta['value']
                                 if child['name'] == elem]
            try:
                item_meta = matching_children[0]
            except IndexError:
                raise FileNotFoundError
            yield item_meta

    @error_mapper
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """Move a file from source to target on the remote."""
        logger.debug("Trying to move %s (%s) -> %s (%s)", source, expected_source_vid,
                     target, expected_target_vid)
        source_meta = self._verify_version_id(path=source,
                                              version_id=expected_source_vid)

        if expected_target_vid is not None:
            target_meta = self._verify_version_id(path=target,
                                                  version_id=expected_target_vid)
            parent_id = target_meta['parentReference']['id']
            parent_drive_id = target_meta['parentReference']['driveId']

        else:
            target_meta_list = list(self._iter_dir_safe(target[:-1]))
            parent_id = target_meta_list[-1]['id']
            parent_drive_id = self._drive_id_from_meta_list(target_meta_list)

        payload = {
            'parentReference': {
                'id': parent_id,
                'driveId': parent_drive_id,
            },
            'name': target[-1]}

        if self.group_id is not None:
            # This is a hack:
            # the groups endpoint does not require a parent_drive_id
            # And in certain cases the parent_drive_id taken from _drive_id_from_meta_list
            # will be the drive_id of the user. Therefore it's afer to remove.
            del payload['parentReference']['driveId']

        # logger.info('### payload: %s', payload)
        url = self.urls.patch(item_meta=source_meta, group_id=self.group_id)

        try:
            response_json = self.api.patch(url=url, json=payload).json()
        except requests.exceptions.HTTPError as error:
            if error.response.status_code == 409:
                self.delete(target, self._version_id_from_meta(target_meta))
                response_json = self.api.patch(url=url, json=payload).json()
            else:
                raise error

        new_version_id = self._version_id_from_meta(response_json)
        # logger.info('### new_version_id: %s', new_version_id)
        return new_version_id

    def _drive_id_from_meta_list(self, target_meta_list):
        """Extract a drive id from a list of meta items which represent a path."""
        try:
            target_meta_list[-1]['parentReference']['driveId']
        except KeyError:
            logger.info('unable to find drive_id, reverting to own drive_id: %s ',
                        self.api.drive_id)
            return self.api.drive_id

    @error_mapper
    def open_read(self, path, expected_version_id=None):
        """Download a file from the remote."""
        if expected_version_id is not None:
            self._verify_version_id(path, version_id=expected_version_id)
        # logger.info('### path: %s', path)
        url = self.urls.download(to_path(path), group_id=self.group_id)
        raw = self.api.download(url)
        return raw

    @error_mapper
    def delete(self, path, original_version_id=None):
        """Delete a item at the provided path."""
        item_meta = self._verify_version_id(path, version_id=original_version_id)
        url = self.urls.delete(path=to_path(path),
                               item_meta=item_meta,
                               group_id=self.group_id)
        self.api.delete(url)

    @error_mapper
    def write(self, path, file_obj, original_version_id=None, size=None):
        """Write a file to the given path on the remote.

        #TODO: see if If-Match headers work with graph api.
        It implicitly creates all intermeditate folders if necessary.
        """
        if size is None:
            raise ValueError('OneDrive requires a size to write')

        # seperate path into filename and parent_path
        filename = path[-1]
        parent_path = path[:-1]

        if original_version_id:
            self._verify_version_id(path, original_version_id)

        # This retrieving the parent_id is only needed if we are dealing with a group,
        # otherwise the path can be used.
        if self.group_id is not None:
            parent_meta_list = list(self._iter_dir_safe(parent_path))
            parent_id = parent_meta_list[-1]['id']
        else:
            parent_id = None

        if size <= UPLOAD_FRAGMENT_SIZE_MIN:
            url = self.urls.upload(parent_path=to_path(parent_path),
                                   filename=filename,
                                   group_id=self.group_id,
                                   parent_id=parent_id)

            item_meta = self.api.put(url=url, file_obj=file_obj).json()
        else:
            url = self.urls.upload_session(path=to_path(path),
                                           group_id=self.group_id)
            item_meta = self.api.upload_large(url=url, file_obj=file_obj, size=size).json()

        return self._version_id_from_meta(item_meta)

    def _get_meta(self, cc_path):
        """Get the current meta data from the graph api."""
        url = self.urls.path_meta(to_path(cc_path), group_id=self.group_id)
        return self.api.get(url).json()

    def _verify_version_id(self, path, version_id):
        current_meta = self._get_meta(path)
        if version_id == jars.FOLDER_VERSION_ID:
            return current_meta

        current_version_id = self._version_id_from_meta(current_meta)
        if current_version_id != version_id:
            raise jars.VersionIdNotMatchingError(storage_id=self.storage_id,
                                                 version_a=version_id,
                                                 version_b=current_version_id)
        return current_meta

    # pylint: disable=no-self-use
    def _version_id_from_meta(self, item_meta):
        """Extract to correct version_id from the meta.

        This doe not necessarily have to be a method, but it is here to document the
        various opptions which ha
        """
        if is_dir(item_meta):
            return jars.FOLDER_VERSION_ID
        else:
            # cTag: not avaliable for all objects.
            # return item_meta['cTag']

            # quickXorHash: not returned after certain operations.
            # item_meta['file']['hashes']['quickXorHash']

            # eTag is documented as being metadata + content.
            return item_meta['eTag']

            # eTags look like this: "{844257BC-8E1F-42FF-BE48-BCC65A27A0F8},2"
            # attempt to strip down to cTag component.
            # return re.findall(r'\{(.*)\}', item_meta['eTag'])

            # final option:
            # return (item_meta['size'], item_meta['lastModifiedDateTime'])
    # pylint: enable=no-self-use

    def create_public_sharing_link(self, path):
        """Has not yet been implemented for odb."""
        raise NotImplementedError

    def create_open_in_web_link(self, path):
        """Has not yet been implemented for odb."""
        raise NotImplementedError

    def create_user_name(self):
        """Return a username for OneDrive for Business.

        In this case the username will be the displayName, obtained using
        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/resources/users
        """
        url = self.urls.build(endpoint='me')
        response = self.api.get(url).json()
        if response['displayName'] != '':
            return response['displayName']
        return response['mail']
