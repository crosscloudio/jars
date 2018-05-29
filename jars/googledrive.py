"""
Implementation of google drive for crosscloud using GoogleDrive REST API 3.0

https://developers.google.com/drive/v3/reference/

Caveats
-------
If you are experiencing problems with the downloads in the webinterface of google its probably
because you are logged into multiple google accounts.
"""
import contextlib
import copy
import logging
import urllib.parse
import sys

import dateutil.parser
import requests.exceptions
from bushn import IndexingNode, NodeChange

import jars
from jars import (IS_DIR, METRICS, AuthenticationError, InvalidOperationError,
                  SharedFolder, StorageMetrics, StorageOfflineError)
from jars.request_utils import error_mapper
from jars.streaming_utils import FragmentingChunker

logger = logging.getLogger(__name__)

VERSION_FIELD = 'md5Checksum'

FIELDS = 'id,mimeType,name,parents,properties,size,trashed,shared,modifiedTime,' \
         'permissions(emailAddress,id),{}'.format(VERSION_FIELD)

MIMETYPE_FOLDER = 'application/vnd.google-apps.folder'

MAPPER_CURRENTLY_NOT_POSSIBLE_REASONS = ['userRateLimitExceeded', 'rateLimitExceeded',
                                         'sharingRateLimitExceeded']
MAPPER_INVALID_OP_REASONS = ['appNotAuthorizedToFile', 'insufficientFilePermissions',
                             'domainPolicy']
MAPPER_SEVERE_REASONS = ['dailyLimitExceeded']

SHARED_WITH = '_shared_with'


def gdrive_error_mapper(fun):
    """ A decorator which maps the Google Drive specific
     class:`requests.exceptions.HTTPError`
     from requests to jars exceptions.

     This handles ONLY Google Drive specific stuff on top of the standard error handler
     from class:`cc.request_utils.error_mapper` - ONLY USE BOTH COMBINED

     """

    def new_fun(*args, **kwargs):
        """ function wrapper """
        try:
            return fun(*args, **kwargs)
        except requests.exceptions.HTTPError as exception:
            try:
                error_dict = exception.response.json()
                error = error_dict.get('error', {}).get('errors', [{}])[0]
                reason = error.get('reason', '')
            except BaseException:
                # If any error happens during parsing - reraise the old one
                raise exception
            if exception.response.status_code == 403:
                if reason in MAPPER_CURRENTLY_NOT_POSSIBLE_REASONS:
                    raise jars.CurrentlyNotPossibleError(exception.response.text)
                elif reason in MAPPER_INVALID_OP_REASONS:
                    raise jars.InvalidOperationError(exception.response.text)
                elif reason in MAPPER_SEVERE_REASONS:
                    raise jars.SevereError(exception.response.text)
                else:
                    raise
            else:
                raise

    return new_fun


class GoogleDrive(jars.OAuthBasicStorage):
    """ Main class to use google drive"""

    # Credentials you get from registering a new application
    client_identificator = 144880602865
    client_id = '{}.apps.googleusercontent.com'.format(client_identificator)
    client_secret = 'CLIENT_SECRET'
    redirect_uri = 'http://localhost:9324'

    # OAuth endpoints given in the Google API documentation
    authorization_base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://accounts.google.com/o/oauth2/token"
    scope = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/drive"
    ]
    base_url = 'https://www.googleapis.com/drive/v3/'

    storage_name = "gdrive"
    storage_display_name = "Google Drive"

    def __init__(self, event_sink, storage_id, storage_cred_reader, storage_cred_writer,
                 storage_cache_dir=None, polling_interval=5):
        """

        :param event_sink: sink to report events to
        :param storage_id: unique sotrage id assigned to this storage
        :param storage_cred_reader: reader to reaad credentials or other auth data from
        :param storage_cred_writer: writer to write credentials or other auth data to
        :param storage_cache_dir: cache directory to store cached models at
        :param polling_interval: the intervall to poll for changes from the service
        """
        # pylint: disable=too-many-arguments

        super().__init__(event_sink, storage_id, storage_cred_reader,
                         storage_cred_writer, storage_cache_dir=storage_cache_dir,
                         default_model=IndexingNode(None, indexes=['_id']))

        self.event_poller = None
        self.polling_interval = polling_interval

    def _init_poller(self):
        """initalize poller"""

        def set_offline(value):
            """Set it offline"""
            self.offline = value

        # creating poller getting events from the storage
        return jars.PollingScheduler(
            self.polling_interval, target=self.update_model,
            target_kwargs={'emit_events': True},
            offline_callback=set_offline)

    def check_available(self):
        # check authentication
        try:
            url = urllib.parse.urljoin(self.base_url, 'about?fields=storageQuota,user')
            about = self.oauth_session.get(url)
            error_mapper(about.raise_for_status)()
        except requests.exceptions.HTTPError as exception:
            if exception.response.status_code == 401:
                raise AuthenticationError(storage_id=self.storage_id,
                                          origin_error=exception)
            else:
                raise StorageOfflineError(storage_id=self.storage_id,
                                          origin_error=exception)
        except BaseException as error:
            raise StorageOfflineError(storage_id=self.storage_id, origin_error=error)

    @error_mapper
    @gdrive_error_mapper
    def get_tree(self, cached=False, filtered=True):
        # pylint: disable=arguments-differ, too-many-locals
        logger.debug('requested tree with filter %s', self.filter_tree)
        if cached:
            with self.model.lock:
                if filtered:
                    logger.debug('requested tree with filter %s', self.filter_tree)
                    return jars.utils.filter_tree_by_path(tree=self.model,
                                                          filter_tree=self.filter_tree)
                else:
                    return copy.deepcopy(self.model)

        root = IndexingNode(name=None, indexes=['_id'])

        # fetch and store current cursor
        url = urllib.parse.urljoin(self.base_url, 'changes/startPageToken')
        token = self.oauth_session.get(url)
        token.raise_for_status()
        root.props['_cursor'] = token.json()['startPageToken']

        # get root id
        url = urllib.parse.urljoin(self.base_url, 'files/root?fields=id')
        root_id = self.oauth_session.get(url)
        root_id.raise_for_status()
        root.props['_id'] = root_id.json()['id']

        # fetch metrics
        url = urllib.parse.urljoin(self.base_url, 'about?fields=storageQuota,user')
        about = self.oauth_session.get(url)
        about.raise_for_status()
        metrics = about.json()

        # this is relevant to client#970
        total_space = int(metrics['storageQuota'].get('limit', sys.maxsize))
        free_space = total_space - int(metrics['storageQuota']['usageInDrive'])
        root.props[METRICS] = StorageMetrics(storage_id=self.storage_id,
                                             free_space=free_space,
                                             total_space=total_space)
        # fetch tree
        url = urllib.parse.urljoin(
            self.base_url,
            'files')

        page_token = None

        nodes = []

        # fetch the whole tree into the parent_map
        while True:
            params = {'pageSize': '1000',
                      'q': 'trashed=false',
                      'orderBy': 'folder',
                      'fields': 'nextPageToken,files(' + FIELDS + ')'}
            if page_token is not None:
                params['pageToken'] = page_token
            files_resp = self.oauth_session.get(
                url, params=params)

            files_resp.raise_for_status()
            resp_json = files_resp.json()
            files = resp_json['files']
            page_token = resp_json.get('nextPageToken', None)

            for file in files:
                if 'parents' in file and is_relevant_file(file):
                    for parent_id in file['parents']:
                        # for each parent add this element
                        if is_relevant_file(file):
                            nodes.append(NodeChange(action='UPSERT',
                                                    parent_id=parent_id,
                                                    name=file['name'],
                                                    props=gdrive_to_node_props(file)))

            if page_token is None:
                break

        root.add_merge_set_with_id(nodes, key='_id')
        self._adjust_share_ids(nodes)

        self.offline = False

        if filtered:
            logger.debug('requested tree with filter %s', self.filter_tree)
            root = jars.utils.filter_tree_by_path(root, self.filter_tree)
        return root

    def _get_children(self, parent_id):
        body = {'q': "'{}' in parents and trashed=false".format(
            parent_id), 'fields': 'files({})'.format(FIELDS)}

        response = self.oauth_session.get(
            'https://www.googleapis.com/drive/v3/files',
            params=body)

        response.raise_for_status()

        result = []
        for file in response.json()['files']:
            if not is_relevant_file(file):
                continue
            props = gdrive_to_node_props(file)
            result.append((file['name'], props))
        return result

    @error_mapper
    @gdrive_error_mapper
    def get_tree_children(self, path):
        """
        :param path: if path is a list, it is used like a path, if a string, it is used as
         parent_id
        :param ids: if the function should return the _id field in the properties
        :return:
        """
        if path:
            parent_id = self._path_to_file_id(path)
        else:
            # [] is the root path, no need for extra resolve
            parent_id = 'root'

        return self._get_children(parent_id)

    def start_events(self):
        """ starts the event poller """
        if (self.event_poller and not self.event_poller.is_alive()) \
                or not self.event_poller:
            # recreate poller instance
            self.event_poller = self._init_poller()
            self.event_poller.start()

    def stop_events(self, join=False):
        if self.event_poller:
            self.event_poller.stop(join=join)

    def clear_model(self):
        self.model = IndexingNode(None, indexes=['_id'])

    def get_internal_model(self):
        return self.model

    def update(self):
        with self.model.lock:
            if '_cursor' not in self.model.props:
                # no model ever fetched, fetch model
                self.model = self.get_tree(filtered=False)
            else:
                self.update_model(emit_events=False)

    @error_mapper
    @gdrive_error_mapper
    def update_model(self, emit_events=False):
        """
        updates a model with a given cursor and returns the new cursor
        if emit_events is set it also triggers events on changes
        """

        # TODO lock less, create iterator
        with self.model.lock:
            mergeset = []
            assert '_cursor' in self.model.props

            page_token = str(self.model.props['_cursor'])

            while page_token is not None:
                urlparams = {'pageToken': page_token,
                             'includeRemoved': 'true', 'pageSize': '1000',
                             'fields': 'changes,newStartPageToken,nextPageToken'}

                url = urllib.parse.urljoin(self.base_url, 'changes')

                changes_resp = self.oauth_session.get(
                    url, params=urlparams)

                changes_resp.raise_for_status()
                changes = changes_resp.json()
                # logger.debug(threading.current_thread().name)
                # logger.debug(changes)
                page_token = changes.get('nextPageToken')
                if 'newStartPageToken' in changes:
                    self.model.props['_cursor'] = changes['newStartPageToken']

                for change in changes['changes']:
                    merges = transform_gdrive_change(change)
                    mergeset.extend(merges)

            logger.info("Finished fetching updates from gdrive.")

            with contextlib.ExitStack() as stack:
                if emit_events:
                    stack.enter_context(jars.TreeToSyncEngineEngineAdapter(
                        node=self.model, storage_id=self.storage_id,
                        sync_engine=self._event_sink))
                left_overs = self.model.add_merge_set_with_id(mergeset, '_id', using_update=True)
                if left_overs:
                    logger.info('Left overs from delta: %s', left_overs)
                logger.debug('After update')
                self._adjust_share_ids(mergeset)
                logger.debug('After _adjust_share_ids')

    def _adjust_share_ids(self, mergeset):
        """Helper to identify the unique share ids on gdrive, if the permissions of the parent are
         different then the ones on the children, we assume this is a different share"""

        for change in mergeset:
            action, parent_id, name, props = change
            logger.info("_adjust_share_ids, change: %s", change)

            # Removing files does not change any share_ids
            if action == 'DELETE':
                logger.debug("Not handling DELETEs")
                continue

            # The node isn't shared with anyone, skip it
            if SHARED_WITH not in props:
                logger.debug("Node isn't shared with anyone, skipping")
                continue

            # The node does not exist in our index(?)
            if not props['_id'] in self.model.index['_id']:
                logger.debug("Node does not exist in our model")
                continue

            # Get a reference to the props dict of our model
            props = self.model.index['_id'][props['_id']].props
            shared_with = props[SHARED_WITH]

            # Get the node's parent - this can be None, if the node is root
            parent_node = self.model.index['_id'].get(parent_id, None)

            logger.info(
                "Checking change for file '%s' (shared_with: %s, parent_node shared_with: %s)",
                name, shared_with,
                set() if parent_node is None else parent_node.props.get(SHARED_WITH, set()))

            if parent_node is None or shared_with != parent_node.props.get(SHARED_WITH, set()):
                # Either we are looking at root, or the node has been shared with different people
                #  than it's parent -> it's a different share

                logger.debug('setting share id for: %s (Parent: %s, Node: %s) to %s',
                             name,
                             set() if parent_node is None else
                             parent_node.props.get(SHARED_WITH, set()),
                             props.get(SHARED_WITH, set()),
                             props['_id'])

                props[jars.SHARE_ID] = props['_id']
            else:
                # The node has the same list of people it is shared to as it's parent
                #  -> they belong to the same share
                # Remove the share_id on the node, we only need it on the parent
                logger.debug('Removing share_id from %s (Parent: %s, Node: %s)',
                             name, parent_node.props.get(SHARED_WITH, set()),
                             props.get(SHARED_WITH, set()))
                props.pop(jars.SHARE_ID, None)

    @error_mapper
    @gdrive_error_mapper
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        new_fields = {}
        params = {'fields': 'mimeType,' + VERSION_FIELD}

        # rename
        if source[-1] != target[-1]:
            new_fields['name'] = target[-1]

        target_id = None
        source_id = None
        source_dir_id = None

        with self.model.lock:
            try:
                source_node = self.model.get_node(source)
            except KeyError:
                raise FileNotFoundError()
            source_id = source_node.props['_id']
            source_dir_id = source_node.parent.props['_id']
            try:
                target_node = self.model.get_node(target)
                target_id = target_node.props['_id']
            except KeyError:
                target_id = None

        # move to another dir?
        if source[:-1] != target[:-1]:
            target_dir_id = self.make_dir(target[:-1], return_id=True)
            params['addParents'] = target_dir_id
            params['removeParents'] = source_dir_id

        # before the actual action check the version
        self._check_version_id(source_id, expected_source_vid, source)

        if target_id is not None:
            # replace also involves deletion of the orignal item,
            # version checking is done there
            self.delete(target, expected_target_vid)

        request = self.oauth_session.patch(
            urllib.parse.urljoin(self.base_url, 'files/{}'.format(source_id)),
            json=new_fields, params=params
        )
        request.raise_for_status()

        file = request.json()

        if file['mimeType'] == MIMETYPE_FOLDER:
            return IS_DIR
        else:
            return file[VERSION_FIELD]

    def _check_version_id(self, file_id, expected_version_id, path=None):
        url = urllib.parse.urljoin(self.base_url, 'files/{}'.format(file_id))
        if expected_version_id is not None:
            response = self.oauth_session.get(url, params={
                'fields': 'mimeType,' + VERSION_FIELD})
            if expected_version_id == 'is_dir' \
                    and response.json()['mimeType'] == MIMETYPE_FOLDER:
                # its fine, dir to dir
                return
            response.raise_for_status()
            if response.json()[VERSION_FIELD] != expected_version_id:
                raise jars.VersionIdNotMatchingError(
                    self.storage_id,
                    path=path,
                    version_b=expected_version_id,
                    version_a=response.json()[VERSION_FIELD])

    @error_mapper
    @gdrive_error_mapper
    def open_read(self, path, expected_version_id=None):
        file_id = self._path_to_file_id(path)

        self._check_version_id(file_id, expected_version_id, path)

        url = urllib.parse.urljoin(self.base_url, 'files/{}'.format(file_id))

        # 'Accept-Encoding' is removed from the header until
        # https://github.com/shazow/urllib3/issues/437
        # is fixed and merged into requests
        response = self.oauth_session.get(url, params={'alt': 'media'},
                                          headers={'Accept-Encoding': None}, stream=True)
        response.raise_for_status()

        response.raw.decode_content = True
        return response.raw

    @error_mapper
    @gdrive_error_mapper
    def make_dir(self, path, return_id=False):
        # pylint: disable=arguments-differ

        # which parents to create
        # this needs to be locket until everything is done, since it might run parallel
        with jars.TreeToSyncEngineEngineAdapter(
                node=self.model, storage_id=self.storage_id,
                sync_engine=self._event_sink):
            parent = self.model
            # iterate the path
            for elem in path:
                if parent.has_child(elem):
                    parent = parent.get_node([elem])
                else:
                    url = urllib.parse.urljoin(self.base_url, 'files/')
                    body = {'mimeType': 'application/vnd.google-apps.folder',
                            'name': elem,
                            'parents': [parent.props['_id']]
                            }
                    resp = self.oauth_session.post(
                        url, json=body, params={'fields': FIELDS})
                    resp.raise_for_status()

                    # node.props['_id'] = resp.json()['id']
                    props = gdrive_to_node_props(resp.json())
                    node = parent.add_child(name=elem, props=props)
                    parent = node
            if return_id:
                return self.model.get_node(path).props['_id']
            else:
                return 'is_dir'

    @error_mapper
    @gdrive_error_mapper
    def _path_to_file_id(self, path):
        """
        resolves the path via the model or if this does not work via http requests
        """
        try:
            with self.model.lock:
                node = self.model.get_node(path)
                return node.props['_id']
        except KeyError:
            # try to resolve the path via requests
            path_elm_id = 'root'
            for path_elm in path:
                children = self._get_children(path_elm_id)
                path_elm_id = \
                    next((props['_id'] for name, props in children if name == path_elm),
                         None)

            if path_elm_id is not None:
                return path_elm_id

            raise FileNotFoundError("File does not exist", path)

    @error_mapper
    @gdrive_error_mapper
    def delete(self, path, original_version_id):
        """ Delete can be done in 2 ways on GoogleDrive: either with a permanent delete by using
        https://developers.google.com/drive/v3/reference/files/delete or set trashed to true with a
        patch https://developers.google.com/drive/v3/reference/files/update.


        """

        file_id = self._path_to_file_id(path)
        file_url = urllib.parse.urljoin(self.base_url, 'files/' + str(file_id))

        # fetch current version id since Google Drive has node If-Match header
        if original_version_id is not None:
            version_id_resp = self.oauth_session.get(
                file_url, params={'fields': 'mimeType,' + VERSION_FIELD})
            version_id_resp.raise_for_status()
            response = version_id_resp.json()
            if response['mimeType'] == 'application/vnd.google-apps.folder':
                version_id = 'is_dir'
            else:
                version_id = response[VERSION_FIELD]
            if version_id != original_version_id:
                raise jars.VersionIdNotMatchingError(
                    self.storage_id, version_a=version_id, version_b=original_version_id)

        resp = self.oauth_session.patch(file_url, json={'trashed': True})
        resp.raise_for_status()

    @error_mapper
    @gdrive_error_mapper
    def write(self, path, file_obj, original_version_id=None, size=0):
        """
        https://developers.google.com/drive/v3/web/manage-uploads
        """
        # pylint: disable=too-many-locals,too-many-statements

        parent_id = None
        node_id = None
        http_verb = ''

        with self.model.lock:
            with contextlib.suppress(KeyError):
                parent = self.model.get_node(path[:-1])
                parent_id = parent.props['_id']
                with contextlib.suppress(KeyError):
                    node = parent.get_node([path[-1]])
                    node_id = node.props['_id']

        # create parent and fetch id
        if parent_id is None:
            self.make_dir(path[:-1])
            with self.model.lock:
                parent = self.model.get_node(path[:-1])
                parent_id = parent.props['_id']

        url = 'https://www.googleapis.com/upload/drive/v3/files'

        # check version id, if there is one to check
        if original_version_id is not None:
            res = self.oauth_session.get(
                'https://www.googleapis.com/drive/v3/files/{}'.format(node_id),
                params={'fields': VERSION_FIELD}
            )
            res.raise_for_status()
            if res.json()[VERSION_FIELD] != original_version_id:
                raise jars.VersionIdNotMatchingError(
                    self.storage_id,
                    version_a=res.json()[VERSION_FIELD],
                    version_b=original_version_id)

        body = {}  # 'parents': [parent_id], 'name': path[-1]}
        if node_id is not None:
            http_verb = 'PATCH'
            body['fileId'] = node_id
            url += '/' + node_id
        else:
            http_verb = 'POST'
            body['parents'] = [parent_id]
            body['name'] = path[-1]

        # read the first kb to see if it is an empty file
        # that is a workaround for https://github.com/kennethreitz/requests/issues/3066
        first_chunk = file_obj.read(1024 * 16)

        response = self.oauth_session.request(
            http_verb,
            url, json=body,
            params={'uploadType': 'resumable',
                    'fields': FIELDS},
            #  headers={'X-Upload-Content-Length': str(size)}
        )

        response.raise_for_status()
        upload_url = response.headers['Location']

        if not first_chunk:
            response = self.oauth_session.put(upload_url)
        else:
            chunker = FragmentingChunker(file_obj, first_chunk=first_chunk,
                                         chunk_size=1024)
            headers = {}
            if size:
                headers['Content-Range'] = 'bytes 0-{}/{}'.format(size - 1, size)

            response = self.oauth_session.put(
                upload_url, data=iter(chunker),
                headers=headers
            )

        response.raise_for_status()

        new_file = response.json()
        with jars.TreeToSyncEngineEngineAdapter(
                node=self.model, storage_id=self.storage_id,
                sync_engine=self._event_sink):
            props = gdrive_to_node_props(new_file)
            if parent.has_child(new_file['name']):
                parent.get_node([new_file['name']]).props.update(props)
            else:
                parent.add_child(new_file['name'], props)

        return new_file[VERSION_FIELD]

    supports_open_in_web_link = True

    @error_mapper
    @gdrive_error_mapper
    def create_open_in_web_link(self, path):
        try:
            file_id = self._path_to_file_id(path)
            response = self.oauth_session.get(
                'https://www.googleapis.com/drive/v3/files/{}'.format(file_id),
                params={'fields': 'webViewLink'}
            )
            response.raise_for_status()

            return response.json()['webViewLink']
        except (TypeError, FileNotFoundError) as ex:
            raise InvalidOperationError(self.storage_id, ex)

    supports_sharing_link = False

    supports_serialization = True

    def create_public_sharing_link(self, path):
        raise NotImplementedError

    def serialize(self):
        """
        See docs from super.
        """
        # letting super serialize the model
        super(GoogleDrive, self).serialize()

    @classmethod
    def _oauth_get_unique_id(cls, oauth_session):
        """
        return unique id for this account
        """
        user_info = get_user_metadata(cls.base_url, oauth_session)
        return user_info['user']['permissionId']

    def get_shared_folders(self):
        """ Returns a list of :class:`jars.SharedFolder`"""
        shared_folders = []
        shared_folders_nodes = [node for node in self.model
                                if node.props.get('shared') is True and
                                node.parent.props.get('shared', False) is False]
        for node in shared_folders_nodes:
            shared_folders.append(SharedFolder(path=node.path,
                                               share_id=node.props['_id'],
                                               sp_user_ids=node.props['_shared_with']))
        return shared_folders

    def create_user_name(self):
        """Return a username for Google Drive.

        In this case the username will be 'displayName', obtained using
        https://developers.google.com/drive/v3/reference/about#resource
        """
        return get_user_metadata(self.base_url, self.oauth_session)['user']['displayName']


def get_user_metadata(base_url, oauth_session):
    """Return current user's metadata."""
    url = urllib.parse.urljoin(base_url, 'about?fields=user')
    response = oauth_session.get(url)
    response.raise_for_status()
    return response.json()


jars.registered_storages.append(GoogleDrive)


def transform_gdrive_change(change) -> [NodeChange]:
    """Transform google drive item properties to crosscloud properties"""
    # logger.debug('CHANGE: %s', change)
    # a remove changes has not size or mimetype, but is relevant
    if not (change.get('removed', False) or is_relevant_file(
            change['file'])):
        logger.debug('not relevant')
        return []

    parent_id = None
    name = None

    merges = []
    if ('removed' in change and change['removed']) or \
            ('trashed' in change['file'] and change['file']['trashed']) or \
            (len(change['file'].get('parents', [])) == 0):
        merges.append(NodeChange(action='DELETE',
                                 parent_id=parent_id,
                                 name=name,
                                 props={'_id': change['fileId']}))
    else:
        for parent_id in change['file']['parents']:
            # add merge element for each parent id
            name = change['file'].get('name')
            merges.append(NodeChange(action='UPSERT',
                                     parent_id=parent_id,
                                     name=name,
                                     props=gdrive_to_node_props(change['file'])))

    # logger.debug('MERGES: %s', merges)
    return merges


def is_relevant_file(file_obj):
    """ decides if a file should be synced or not """
    return ('size' in file_obj and VERSION_FIELD in file_obj) \
        or file_obj['mimeType'] == MIMETYPE_FOLDER


def gdrive_to_node_props(filedict):
    """ Transform a response data to locally used node props for the tree """

    props = {'_id': filedict['id']}
    if filedict['mimeType'] == 'application/vnd.google-apps.folder':
        props['is_dir'] = True
        props['version_id'] = 'is_dir'
        props['size'] = 0
    else:
        props['is_dir'] = False
        props['size'] = int(filedict['size'])
        props['version_id'] = filedict[VERSION_FIELD]

    if filedict['shared']:
        props[jars.SHARED] = True
        props['public_share'] = False
        props['_shared_with'] = set()
        # props['share_id'] = filedict['id']
        for elem in filedict.get('permissions', []):
            props['_shared_with'].add(elem['id'])
            if elem['id'] == 'anyoneWithLink':
                # this is an object which is shared with a public link
                props['public_share'] = True
    else:
        props[jars.SHARED] = False
        # this cannot be dropped - it has to be an empty set so the syncengine
        # updates this as well - if it would be simply not there the SE would not update
        # it
        props['_shared_with'] = set()
    props['modified_date'] = dateutil.parser.parse(filedict['modifiedTime'])
    return props
