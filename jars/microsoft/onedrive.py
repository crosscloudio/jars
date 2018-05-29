"""This module implements a sotrage for Microsoft OneDrive for CrossCloud.

It contains:
- :py:class:~`OneDriveApi`, which wrapps the the api decribed at
https://dev.onedrive.com/README.htm
- :py:class:~`DeltaIterator`, Which can be used to iterate over changes of a certain node.
- various functions for tranforming items and trees.
- :py:class:~`OndeDrive`, the actual subclass of :py:class:`jars.BasicStorage
- :py:class:~`OneDriveBusiness` a further storage implementation for OneDriveBusiness

A few things to keep in mind when dealing with onedrive:
- Change facets are not always in tree order
- Change facets do not always provide a parent reference.
- Remote items are items shared with the user aka share_root
- Shared items are items the user shares with other users.
- Note the subtle difference between the drive and drives endpoints.


@todo: how threadsafe is the oauth write_credentials
TODO: rename sp_user_id to drive id for consistency
"""
# pylint: disable=too-many-arguments
import contextlib
import functools
import logging
import urllib

from urllib.parse import urljoin

import dateutil.parser

import requests
from requests import HTTPError
import bushn


import jars
from jars import SharedFolder
from jars.request_utils import error_mapper as default_error_mapper
from jars.streaming_utils import Fragmenter

logger = logging.getLogger(__name__)


"""Fields to request for various endpoints.
"""

DELTA_TOKEN = '_delta_token'
"""Key used in node props to stash the delta_token if a DeltaIterator, has been used previously.
"""

ONEDRIVE_PRIVATE_API_URL = 'https://api.onedrive.com/v1.0/'
"""The root of the onedrive api
"""

UPLOAD_FRAGMENT_SIZE = 1024 * 320 * 6
"""This is used for fragmenting uploads, according to the`OneDrive documentation
<https://dev.onedrive.com/items/upload_large_files.htm#best-practices>`_ this
should be a multiple of 320 KiB
"""

UPLOAD_FRAGMENT_SIZE_MIN = 8 * 1024
"""file size, used to decide if large file upload method should be used or just `PUT`"""


ERROR_MAP = jars.request_utils.ERROR_MAP.copy()
ERROR_MAP[409] = jars.VersionIdNotMatchingError
"""Onedrive for business uses HTTP 409 if version IDs are not matching
We use the extenden error map
this is not a correct RFC behavior!!!
"""

error_mapper = functools.partial(default_error_mapper, error_map=ERROR_MAP)
"""Setup error mapper with appended 409 handeled"""


def item_endpoint(item_id, drive_id=None, suffix=None):
    """Return the canonical endpoint for an item based on its drive_id and the item_id

    to adress items owned by this user, leave the drive_id None
    """
    if drive_id is not None:
        drive_id = 'drives/{drive_id}'.format(drive_id=drive_id)
    else:
        drive_id = 'drive'

    endpoint = '{drive}/items/{item_id}/'.format(drive=drive_id, item_id=item_id)

    if suffix:
        endpoint += suffix
    return endpoint


def child_enpoint(parent_item_id, filename, drive_id=None):
    """Return a child content endpoint based on drive_id, parent_item_id, and filename
    """
    endpoint = item_endpoint(item_id=parent_item_id, drive_id=drive_id)
    endpoint += 'children/{}/content'.format(filename)
    return endpoint


def upload_session_endpoint(parent_item_id, filename, drive_id=None):
    """Return an endpoint required to start an upload session

    https://dev.onedrive.com/items/upload_large_files.htm
    """
    endpoint = item_endpoint(item_id=parent_item_id, drive_id=drive_id, )
    # remove trailing forwardslash
    endpoint = endpoint[:-1]
    endpoint += ':/{filename}:/upload.createSession'.format(filename=filename)
    return endpoint


def get_shared_with_ids(share_info):
    """Extract the user ids from share_info dict recieved from the permissions endpoint.

    Returns a set of the user ids or an empty set if None are avaliable.

    :param: share_info dict of share information relevant to a single OneDrive item.
    """
    share_ids = [item.get('grantedTo',
                          {}).get('user',
                                  {}).get('id') for item in share_info['value']]
    if share_ids == [None]:
        return set()
    return set(share_ids)


def raise_for_status(response):
    """Make raise_for_status a function, so it can be passed to get and post requests.
    """
    response.raise_for_status()


def raise_for_onedrive(response):
    """Raise a VersionIdNotMatchingErrorConvert if server returns `if-match` or `if=none-match`."""
    # if the format of the version id is not correct the server throws a 400
    if response.status_code == 400:
        if 'if-match' in response.text.lower() or \
                'if-none-match' in response.text.lower():
            raise jars.VersionIdNotMatchingError('')

    raise_for_status(response)


def create_new_model(api, storage_id):
    """Create a new root node, by calling the api and setting the props accordingly.
    """
    drive_info = api.get(endpoint='drive').json()
    root_info = api.get(endpoint='drive/root:/:/',
                        params={'select': 'id'}).json()

    model = bushn.IndexingNode(name=None, indexes=['_id'])

    model.props['metrics'] = jars.StorageMetrics(
        storage_id,
        free_space=drive_info['quota']['remaining'],
        total_space=drive_info['quota']['total'])

    root_id = root_info['id']
    model.props['_id'] = root_id
    return model


def iter_share_roots(model):
    """Extract nodes which are shared from other users to this account.

    Note: The siblings of a share_root are not included in the root delta iterator.
    """
    yield from [node for node in model if node.props.get('_share_root') is True]


def is_dir(item_meta):
    """Determine if an item is a directory based on the meta data provided.
    """
    return 'folder' in item_meta or 'remoteItem' in item_meta


class OneDriveApi:
    """Wrapper for Onedrive API.

    The get method returns the full response and can raise_for_status if need be.
    The various get_... methods define the specific endpoints, and convert the response to json.

    Not all of these methods are explicitly used by the implementaiont, but are usefull for
    debugging what state a Onedrive account is in.
    """
    item_fields = None

    prefix = 'oneDrive'
    """Certain enpoints need to be prefixed.
    See: https://dev.onedrive.com/direct-endpoint-differences.htm#methods"""

    def __init__(self, session, api_root, drive_id):
        """Wrap the oauth_session in a class for consistent access to the endpoints.

        docs: https://dev.onedrive.com/README.htm
        """
        self.drive_id = drive_id
        self.api_root = api_root
        self.session = session

    def extract_ids(self, item_meta):
        """Return drive and item id and required by the various endpoints.
        """
        item_id = get_item_id(item_meta)

        drive_id = item_id.split('!')[0].lower()
        if drive_id == self.drive_id:
            drive_id = None

        return drive_id, item_id

    def get(self, url=None, endpoint=None, status_check=raise_for_status, **kwargs):
        """Make a get request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        This is the method all other get_methods in this class should call.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response prior to returning \
                             default to `raise_for_status` function

        :param kwargs: Are passed to the get request.
        """
        if url is None:
            url = urljoin(self.api_root, endpoint)

        try:
            response = self.session.get(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.get() failed to pass unexpected keyword argument requests.')
            raise

        logger.info('GET [%s:%0.2fs] %s', response.status_code,
                    response.elapsed.total_seconds(), response.url)

        # use the status_check function to raise for status or some derivative.
        if callable(status_check):
            status_check(response)

        return response

    def post(self, url=None, endpoint=None, status_check=raise_for_status, **kwargs):
        """Make a post request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        This is the method all other post_methods in this class should call.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response, default to `raise_for_function`.
        passing any non callable such as False will skip the check.

        all other kwargs are passed to the post request.
        """
        if url is None:
            url = urljoin(self.api_root, endpoint)

        try:
            response = self.session.post(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.post() failed to pass unexpected keyword argument to requests.')
            raise
        logger.info('POST [%s:%0.2fs] %s', response.status_code,
                    response.elapsed.total_seconds(), response.url)

        # use the status_check function to raise for status or some derivative.
        if callable(status_check):
            status_check(response)

        return response

    def delete(self, url=None, endpoint=None, status_check=raise_for_status, **kwargs):
        """Make a delete request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response, default to `raise_for_function`.
        passing any non callable such as False will skip the check.

        all other kwargs are passed to the delete request.
        """
        if url is None:
            url = urljoin(self.api_root, endpoint)
        try:
            response = self.session.delete(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.delete() failed to pass unexpected keyword argument requests.')
            raise

        if callable(status_check):
            status_check(response)

        return response

    def patch(self, url=None, endpoint=None, status_check=raise_for_status, **kwargs):
        """Make a patch request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response, default to `raise_for_function`.
        passing any non callable such as False will skip the check.

        all other kwargs are passed to the patch request.
        """
        if url is None:
            url = urljoin(self.api_root, endpoint)
        try:
            response = self.session.patch(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.patch() failed to pass unexpected keyword argument requests.')
            raise

        if callable(status_check):
            status_check(response)

        return response

    def post_dir(self, parent_id, parent_drive_id, name, status_check=raise_for_onedrive):
        """Make a post request which creates a directory on OneDrive

        https://dev.onedrive.com/items/create.htm
        """
        endpoint = item_endpoint(item_id=parent_id,
                                 drive_id=parent_drive_id,
                                 suffix='children')

        json_data = {"name": name,
                     "folder": {}}
        return self.post(endpoint=endpoint, json=json_data, status_check=status_check)

    def download(self, drive_id, item_id):
        """Download an item based on its item_id
        """

        # 'Accept-Encoding' is removed from the header until
        # https://github.com/shazow/urllib3/issues/437
        # is fixed and merged into requests
        headers = {'Accept-Encoding': None}
        endpoint = item_endpoint(item_id=item_id, drive_id=drive_id, suffix='content')

        response = self.get(endpoint=endpoint,
                            status_check=raise_for_onedrive,
                            stream=True,
                            headers=headers)

        response.raw.decode_content = True
        return response.raw

    def upload(self, drive_id, parent_id, filename, file_obj, size):
        """Upload file using the appropriate method.
        """

        if size <= UPLOAD_FRAGMENT_SIZE_MIN:
            logger.debug('Uploading file %s (size:%d) using put method',
                         filename, size)
            response = self.upload_small(drive_id=drive_id,
                                         parent_id=parent_id,
                                         filename=filename,
                                         file_obj=file_obj)
        else:
            logger.debug('Uploading file %s (size:%d) using upload session',
                         filename, size)
            response = self.upload_large(drive_id=drive_id,
                                         parent_id=parent_id,
                                         filename=filename,
                                         file_obj=file_obj,
                                         size=size)
        return response

    def upload_small(self, drive_id, parent_id, filename, file_obj):
        """Upload the file with the simple item upload

        This is very fast for small files, since it creates the directories implicitly and
        only needs one request

        https://dev.onedrive.com/items/upload_put.htm
        """

        endpoint = child_enpoint(
            drive_id=drive_id, parent_item_id=parent_id, filename=filename)

        url = self.api_root + endpoint

        response = self.session.put(url,
                                    data=file_obj.read(),
                                    headers={})

        raise_for_onedrive(response)

        return response

    def upload_large(self, drive_id, parent_id, filename, file_obj, size):
        """Use the upload large files api in chunks

        https://dev.onedrive.com/items/upload_large_files.htm

        :param first_chunk: first chunk of the file which has been read to determine wether to use
            upload_small or upload_large
        :param file_obj: file to upload
        :param size: size of the file
        :return: response from put of last fragement
        """
        session_endpoint = upload_session_endpoint(drive_id=drive_id,
                                                   parent_item_id=parent_id,
                                                   filename=filename)
        session_url = self.api_root + session_endpoint
        session_response = self.session.post(session_url, headers={})

        session_response.raise_for_status()

        upload_url = session_response.json()['uploadUrl']

        fragment_response = None
        for fragment in Fragmenter(file_obj,
                                   fragment_size=UPLOAD_FRAGMENT_SIZE,
                                   file_size=size):

            headers = {'Content-Length': str(fragment.length),
                       'Content-Range': 'bytes {}-{}/{}'.format(fragment.begin,
                                                                fragment.end, size)}
            fragment_response = self.session.put(upload_url,
                                                 data=fragment.file_obj,
                                                 headers=headers)
            fragment_response.raise_for_status()

        return fragment_response

    def get_delta(self, item_id='root', drive_id=None, delta_token=None):
        """Query delta api endpoint to get changes since the last call as json.

        :param item_id: The OneDrive item id. defaults to root.
        :param delta_token: Token recieved with previous response.

        If item_id is set to 'root', the special endpoint for the root delta is called.
        If no delta_token is provided, all items are returned.
        """
        if self.item_fields is not None:
            params = {'select': ','.join(self.item_fields)}
        else:
            params = {}

        if item_id is 'root':
            endpoint = 'drive/root:/:/{prefix}.delta'.format(
                prefix=self.prefix)

        elif drive_id is not None:
            # This is a share_root, not owned by this user. Notice the 's' at
            # the end of drive
            endpoint = 'drives/{drive}/items/{item_id}/{prefix}.delta'.format(drive=drive_id,
                                                                              item_id=item_id,
                                                                              prefix=self.prefix)
        else:
            endpoint = 'drive/items/{item_id}/{prefix}.delta'.format(item_id=item_id,
                                                                     prefix=self.prefix)

        if delta_token is not None:
            params['token'] = delta_token

        return OneDriveIterator(endpoint=endpoint, api=self, params=params)

    def get_permissions(self, item_id):
        """Query the permissions endpoint for the permissions set on an item.

        :param item_id: The OneDrive item id.

        The permissions endpoint only returns permissions for items of which the user is owner.

        https://dev.onedrive.com/items/permissions.htm
        """
        endpoint = 'drive/items/{item_id}/permissions'.format(item_id=item_id)
        return self.get(endpoint=endpoint).json()

    def get_shared_with_me(self):
        """Query the sharedWithMe endpoint for all items which are shared with the current user.

        https://dev.onedrive.com/drives/shared_with_me.htm
        """
        return self.get(endpoint='drive/{prefix}.sharedWithMe'.format(prefix=self.prefix)).json()

    def get_shared_with_me_from(self, drive_id):
        """Query shared endpoint for items which another OneDrive user shares to this account.

        :param drive_id: the user_id of the user who shares the items with this account.
        https://dev.onedrive.com/drives/shared_by_me.htm
        """
        return self.get(endpoint='drives/{drive_id}/shared'.format(drive_id=drive_id)).json()

    def get_children(self, drive_id, item_id):
        """Query the children endpoint for children of a specific OneDrive item.

        :param drive_id: The OneDrive user_id of the item.
        :param item_id: The OneDrive item id.
        """
        if drive_id is None:
            endpoint = 'drive/items/{item_id}/children'.format(item_id=item_id)
        else:
            endpoint = 'drives/{drive_id}/items/{item_id}/children'.format(drive_id=drive_id,
                                                                           item_id=item_id)
        return self.get(endpoint=endpoint).json()

    def iter_dir_safe(self, path):
        """Same as iter_path but create folders if not avaliable.

        Note: all items of the path will be created, so if a path to a file is needed, the
        filename should be excluded from the path.
        """
        item_meta_iter = self.iter_path(path)

        # yield root_meta
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
                drive_id, item_id = self.extract_ids(dir_meta)
                dir_meta = self.post_dir(name=elem,
                                         parent_drive_id=drive_id,
                                         parent_id=item_id).json()
            yield dir_meta

    def iter_path(self, path):
        """Iter the path on the server, returning the item meta dict if successfull.

        XXX: this requires to many requests. Try to reduce
        :raises FileNotFoundError: when an element of the path cannot be found on the server.
        """
        root_meta = self.get(endpoint='drive/root:/').json()
        drive_id, item_id = self.extract_ids(root_meta)
        if drive_id == self.drive_id:
            drive_id = None

        # yield the root, so list(iter_path(path)) can't be empty
        root_meta['drive_id'] = drive_id
        yield root_meta
        # yield the meta of the rest of the path.
        for elem in path:
            children_meta = self.get_children(
                drive_id=drive_id, item_id=item_id)
            # TODO: Do we need normalization when matching elem to child['name']
            # TODO: Can this return more than 1 element for which the name
            # matches?
            matching_children = [child for child in children_meta['value']
                                 if child['name'] == elem]
            try:
                child_meta = matching_children[0]
            except IndexError:
                raise FileNotFoundError
            drive_id, item_id = self.extract_ids(child_meta)
            yield child_meta


def get_item_id(item_meta):
    """Return the id of the item.

    Depending on who ownes this item, the id needed for addressing it is in a different
    location in the item meta dict.
    """
    if 'remoteItem' in item_meta:
        # the item is a share_root from here a new id is needed.
        item_id = item_meta['remoteItem']['id']
    else:
        item_id = item_meta['id']
    return item_id


class OneDriveIterator:
    """Pagination helper.

    see https://dev.onedrive.com/items/list.htm
    """

    def __init__(self, api, endpoint, params=None):
        self.api = api
        self.endpoint = endpoint
        self.last_response = None
        if params is None:
            self.params = {}
        else:
            self.params = params

    def __iter__(self):
        next_link = None

        while True:
            if next_link is None:
                response_json = self.api.get(
                    endpoint=self.endpoint, params=self.params).json()
            else:
                response_json = self.api.get(url=next_link).json()

            for item in response_json['value']:
                yield item

            self.last_response = response_json

            if '@odata.nextLink' in response_json:
                next_link = response_json['@odata.nextLink']
                # TODO: XXX: This is a hotfix for the issue described here:
                # https://github.com/OneDrive/onedrive-api-docs/issues/535
                # and should be removed as soon as this issue is resolved!
                next_link = next_link.replace(
                    "s('me')/items('root%252F')", "/root:/:")
                # next_link = response_json['@odata.nextLink']

            else:
                break


class OneDrive(jars.OAuthBasicStorage):
    """OneDrive storage class"""
    # pylint: disable=too-many-public-methods
    client_id = 'CLIENT_ID'
    client_secret = 'CLIENT_SECRET'
    redirect_uri = 'http://localhost:9324'
    """Credentials you get from registering a new application"""

    skip_tmp_file = False

    authorization_base_url = "https://login.live.com/oauth20_authorize.srf"
    token_url = "https://login.live.com/oauth20_token.srf"
    """OAuth endpoints given in the Onedrive API documentation"""

    scope = [
        'onedrive.readwrite',
        'wl.offline_access'
    ]
    """Grants read and write permission to all of a user's OneDrive files, including
    files shared with the user. To create sharing links, this scope is required.
    """

    version_id_field = 'cTag'

    item_fields = ['id', 'lastModifiedDateTime', 'name', 'shared', 'folder', 'size',
                   'parentReference', 'cTag', 'deleted', 'file']

    """Which field to use for the version id
    eTag is the other option, but it conflates metadata with content
    """
    API_CLASS = OneDriveApi
    storage_name = "onedrive"
    storage_display_name = "OneDrive"
    supports_serialization = True

    auth = [jars.BasicStorage.AUTH_OAUTH]

    # pylint: disable=too-many-arguments
    def __init__(self, event_sink, storage_id, storage_cred_reader, storage_cred_writer,
                 storage_cache_dir=None, api_root=ONEDRIVE_PRIVATE_API_URL, polling_interval=10):
        """Initializer of the storage

        :param event_sink: sink to report events to
        :param storage_id: unique storage id assigned to this storage
        :param storage_cred_reader: reader that shall be used to read credentials
        :param storage_cred_writer: writer to store credentials or other auth data
        :param storage_cache_dir: directory to cache model
        :param polling_interval: interval with which to poll the server.
        """
        super().__init__(event_sink, storage_id, storage_cred_reader, storage_cred_writer,
                         storage_cache_dir,
                         default_model=bushn.IndexingNode(name=None, indexes=['_id']))

        # todo why not simply set self.event_sink in super()
        self.event_sink = self._event_sink

        self.event_poller = None

        self.drive_id = self._oauth_get_unique_id(
            self.oauth_session, api_root=api_root)
        """The id used by Onedrive to identify this user. aka Drive ID in Onedrive docs"""

        self.api = self.API_CLASS(self.oauth_session, api_root, drive_id=self.drive_id)
        self.polling_interval = polling_interval
        """If a polling interval has been passed, use it, otherwise use the default"""
    # pylint: enable=too-many-arguments

    def _init_poller(self):
        def set_offline(value):
            """Set the offline state."""
            self.offline = value

        def update_callback():
            """Called each polling_interval."""
            self.model = self.get_update(self.model, emit_events=True)

        # creating poller getting events from the storage
        return jars.PollingScheduler(
            self.polling_interval,
            target=update_callback,
            offline_callback=set_offline)

    def check_available(self):
        # check if authenticated
        try:
            _ = self.api.get(endpoint='drive')
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

    def clear_model(self):
        """Reset the model to an empty state.
        """
        self.model = bushn.IndexingNode(None, indexes=['_id'])

    def update(self):
        """Update the interal model of this storage.
        """
        if self.model.props == {}:
            self.model = create_new_model(
                api=self.api, storage_id=self.storage_id)

        self.model = self.get_update(self.model)

    def get_update(self, model=None, emit_events=False):
        """Return an updated version of the provided model.

        If model is set to None, a brand new model is created.

        :param model: model to update. defaults to None
        :param emit_events: wether to trigger events when merging.
        """

        with model.lock:
            # first update the root node
            self._update_node(node=model, emit_events=emit_events)
            # then all the share_roots.
            # Handle deleted shares here because the root update still returns an entry for the
            # share in the tree. Probably a timing issue until it's properly registered.
            for share_root in iter_share_roots(model):
                try:
                    self._update_node(node=share_root, emit_events=emit_events)
                except HTTPError:
                    logger.warning("Could not get data for %s, assuming share is gone",
                                   share_root.path)
                    # XXX: this hotfixes the issue, but there's a deeper problem somewhere
                    # that causes the deletion of the node to fail (add_merge_set_with_id only has
                    # root the root node in the tree)
                    with contextlib.ExitStack() as stack:
                        if emit_events:
                            stack.enter_context(jars.TreeToSyncEngineEngineAdapter(
                                node=model, storage_id=self.storage_id,
                                sync_engine=self._event_sink))
                            share_root.delete()
        return model

    def _update_node(self, node, emit_events=False):
        """Update the model with events from a DeltaIterator on the specified node.
        """
        delta_token = node.props.get(DELTA_TOKEN, None)
        merge_set = []

        delta_iterator = self.api.get_delta(delta_token=delta_token,
                                            item_id=node.props.get('_id'),
                                            drive_id=node.props.get('_drive_id'))
        for item in delta_iterator:
            if item['id'] == node.props['_id']:
                logger.debug('ignoring root')
                continue
            if 'parentReference' not in item:
                logger.debug('ignoring item without parent reference name:%s',
                             item.get('name'))
                continue
            if self.skip_tmp_file and item.get('name', '').startswith('~tmp'):
                # Note: ~tmp files are created when an upload is canceled.
                # TODO: is there a good way to remove these?
                logger.debug('skipping temp file: %s', item['name'])
                continue
            merge_set.append(self._convert_to_merge_tuple(item))
        self.add_merge_set_to_model(
            merge_set=merge_set, node=node, emit_events=emit_events)

        node.props[DELTA_TOKEN] = delta_iterator.last_response['@delta.token']

    def _convert_to_merge_tuple(self, item):
        """Convert a OneDrive item to a mergeable tuple
        """
        name = item.get('name')

        props = {}

        action = 'UPSERT'
        logger.debug("## Delta for: %s", name)
        if 'deleted' in item:
            logger.debug('*** delete for %s', item)
            action = 'DELETE'
            props['_id'] = item['id']
        else:
            props = self.onedrive_item_to_cc_props(item=item, props=props)

        return bushn.NodeChange(action=action,
                                parent_id=item['parentReference']['id'],
                                name=name,
                                props=props)

    def add_merge_set_to_model(self, merge_set, node, emit_events=False):
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

    @error_mapper
    def get_tree(self, cached=False):
        """Use delta-api to fetch all children and then save the token

        seealso: https://dev.onedrive.com/items/view_delta.htm
        """

        if cached:
            model = self.model
        else:
            model = self.get_update(create_new_model(api=self.api,
                                                     storage_id=self.storage_id))

        with self.model.lock:
            copy = jars.utils.filter_tree_by_path(model, self.filter_tree)
        return copy

    def onedrive_item_to_cc_props(self, props, item):
        """Append relevant entries from an api item response to props

        An extra query to the permissions endpoint is required for each item which is
        marked as shared.
        """
        # import pprint
        # logger.info('### pp: %s', pprint.pformat(item))
        props['_drive_id'], props['_id'] = self.api.extract_ids(item)
        props[jars.IS_DIR] = is_dir(item)

        if props['is_dir']:
            props['version_id'] = 'is_dir'
        else:
            props['version_id'] = self.version_id_from_meta(item)
        props['size'] = item.get('size', 0)
        props['modified_date'] = \
            dateutil.parser.parse(item['lastModifiedDateTime'])

        props['_share_root'] = 'remoteItem' in item
        props[jars.SHARED] = 'shared' in item

        if props[jars.SHARED]:
            # In this case, we have to make an extra call to the permisions endpoint,
            # and look who permission is granted to for this share.
            props['share_id'] = item['id']

            owner_id = item['shared']['owner']['user']['id']
            if owner_id == self.drive_id:

                permissions = self.api.get_permissions(item['id'])
                shared_with = get_shared_with_ids(permissions)

                # keep shared_with as private prop, for get_shared_folders
                props['_shared_with'] = shared_with

                # if the shared with is empty, that means it is a public share.
                props['public_share'] = not bool(shared_with)

        if props['_share_root']:
            props['_id'] = item['remoteItem']['id']
            props['share_id'] = item['remoteItem']['id']
            props['_remoteItem_id'] = item['remoteItem']['id']
            props['_drive_id'] = item['remoteItem']['parentReference']['driveId']
            props[jars.SHARED] = False
        return props

    def version_id_from_meta(self, item_meta):
        """Extract the version_id from the item_meta."""
        if is_dir(item_meta):
            return jars.FOLDER_VERSION_ID
        else:
            return item_meta[self.version_id_field]

    @error_mapper
    def get_tree_children(self, path):
        # TODO: pageinate (is that function ever used?)
        item_meta = self.get_item_meta(path)
        drive_id, item_id = self.api.extract_ids(item_meta)

        children_endpoint = item_endpoint(drive_id=drive_id,
                                          item_id=item_id,
                                          suffix='children')

        children = OneDriveIterator(api=self.api, endpoint=children_endpoint)
        return [(item['name'], self.onedrive_item_to_cc_props(props={}, item=item))
                for item in children]

    def get_item_meta(self, path, safe=False):
        """Retrieve Onedrive metadata for an item based on a CC path

        :param path: the path to the item
        :param safe: wether to create directories on the wqs
        :type path: list of strings
        :type safe: bool


        TODO: possible optimisation: See how much of the path is avaliable in the model.
        """
        # Get the metadata either from the model or the server.
        try:
            node = self.model.get_node(path)
            drive_id = node.props['_drive_id']
            item_id = node.props['_id']
            endpoint = item_endpoint(item_id=item_id, drive_id=drive_id)
            metadata = self.api.get(endpoint=endpoint).json()
        except KeyError:
            # node is not in model; is it on the server?
            if safe:
                path_meta_list = list(self.api.iter_dir_safe(path))
            else:
                path_meta_list = list(self.api.iter_path(path))
            metadata = path_meta_list[-1]

        return metadata

    @error_mapper
    def open_read(self, path, expected_version_id=None):
        """Downloads the file as seen from a filesystems perspective.

        Try to extract the information required information from the tree, otherwise fall back to
        the server.

        https://dev.onedrive.com/items/download.htm
        """
        metadata = self.get_item_meta(path)

        # Check that the version id is correct
        if expected_version_id is not None:
            # headers['If-Match'] = expected_version_id
            if self.version_id_from_meta(metadata) != expected_version_id:
                raise jars.VersionIdNotMatchingError(self.storage_id,
                                                     expected_version_id)

        # download using the information provided in the metadata.
        drive_id, item_id = self.api.extract_ids(metadata)

        return self.api.download(drive_id=drive_id, item_id=item_id)

    supports_open_in_web_link = True
    supports_sharing_link = True

    @error_mapper
    def create_open_in_web_link(self, path):
        try:
            item_meta = self.get_item_meta(path)
        except (TypeError, FileNotFoundError) as error:
            # TypeError is raise if path is None
            # FileNotFoundError is raised if the path does not exist.
            raise jars.StorageError(self.storage_id, origin_error=error, path=path)
        return item_meta['webUrl']

    # @error_mapper
    # def create_web_link(self, path):
    #     if path == [] or path is None:
    #         raise jars.StorageError(storage_id=self.storage_id, path=path)
    #     base_url = 'https://onedrive.live.com/'
    #     try:
    #         node = self.model.get_node(path)
    #     except:
    #         raise jars.StorageError(storage_id=self.storage_id, path=path)
    #     parsed_id = urllib.parse.quote_plus(node.props['_id'])
    #     url = '{}?id={}&action=share'.format(base_url, parsed_id)
    #     return url

    @error_mapper
    def create_public_sharing_link(self, path):
        """https://dev.onedrive.com/items/sharing_createLink.htm
        """
        if path == []:
            raise jars.InvalidOperationError("Can't share root")

        item_meta = self.get_item_meta(path)
        drive_id, item_id = self.api.extract_ids(item_meta)

        endpoint = item_endpoint(drive_id=drive_id,
                                 item_id=item_id,
                                 suffix='action.createLink')

        response = self.api.post(endpoint=endpoint, json={'type': 'view'})

        return response.json()['link']['webUrl']

    @error_mapper
    def make_dir(self, path):
        """https://dev.onedrive.com/items/create.htm"""
        # return if root
        if path == []:
            return
        logger.debug('creating directory %s', path)
        path_meta_list = list(self.api.iter_dir_safe(path))
        logger.debug('create dir name %s', path_meta_list[-1]['name'])

        return 'is_dir'

    @error_mapper
    def delete(self, path, original_version_id=None):
        """Deletes a file or directory from onedrive.

        Ondrive first checks if the version_id, which makes sense, but our tests require us to
        throw a 404. In order to achieve this, the metadata of the item is fetched first.
        """
        # This will make a call to the api, which will throw 404 if the item is
        # no longer there.
        item_meta = self.get_item_meta(path)

        if original_version_id is not None and original_version_id != 'is_dir':
            # since the If-Match header are not working reliable we use the
            # data from the response for checking if there is a conflict
            try:
                version_id = self.version_id_from_meta(item_meta)
            except KeyError:
                # Raise if the meta does not contain the required keys to return a vid.
                # TODO: is it better to just return None in version_id_from_meta?
                raise jars.VersionIdNotMatchingError(
                    version_a=original_version_id,
                    version_b=None)

            if version_id != original_version_id:
                raise jars.VersionIdNotMatchingError(
                    version_a=original_version_id,
                    version_b=version_id)

        drive_id, item_id = self.api.extract_ids(item_meta)
        endpoint = item_endpoint(drive_id=drive_id,
                                 item_id=item_id)
        self.api.delete(endpoint=endpoint,
                        status_check=raise_for_onedrive)

    def start_events(self):
        """Start the event poller.
        """
        if (self.event_poller and not self.event_poller.is_alive()) \
                or not self.event_poller:
            # recreate poller instance
            self.event_poller = self._init_poller()
            self.event_poller.start()

    def stop_events(self, join=False):
        self.event_poller.stop()

    # pylint: disable=too-many-locals
    @error_mapper
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """https://dev.onedrive.com/items/move.htm
        """
        # First handle the source
        source_meta = self.get_item_meta(source)
        if expected_source_vid is not None and expected_source_vid != 'is_dir':
            # check it here
            if self.version_id_from_meta(source_meta) != expected_source_vid:
                raise jars.VersionIdNotMatchingError(self.storage_id,
                                                     expected_source_vid)

        # Then handle the target
        target_dir_meta = self.get_item_meta(target[:-1], safe=True)
        target_drive_id, target_item_id = self.api.extract_ids(target_dir_meta)

        target_children = self.api.get_children(drive_id=target_drive_id,
                                                item_id=target_item_id)

        for child in target_children['value']:
            if child['name'] == target[-1]:
                target_meta = child
                break

        if expected_target_vid is not None and expected_target_vid != 'is_dir':
            if self.version_id_from_meta(target_meta) != expected_target_vid:
                raise jars.VersionIdNotMatchingError(self.storage_id, expected_target_vid)

        path_params = {
            'parentReference': {
                'id': target_item_id,
                'driveId': target_drive_id,
            },
            'name': target[-1],
            '@name.conflictBehavior': 'replace'}

        source_drive_id, source_item_id = self.api.extract_ids(source_meta)
        source_endpoint = item_endpoint(drive_id=source_drive_id,
                                        item_id=source_item_id)

        item_meta = self.api.patch(endpoint=source_endpoint,
                                   json=path_params,
                                   status_check=raise_for_onedrive).json()
        if is_dir(item_meta):
            return jars.IS_DIR
        else:
            return self.version_id_from_meta(item_meta)
    # pylint: enable=too-many-locals

    @error_mapper
    def write(self, path, file_obj, original_version_id=None, size=None):
        """https://dev.onedrive.com/items/upload.htm
        """
        if size is None:
            raise ValueError('OneDrive requires a size to write')

        # seperate path into filename and parent_path
        filename = path[-1]
        parent_path = path[:-1]

        # Extract the drive_id and parent_id required to create an item
        if original_version_id:
            path_meta_list = list(self.api.iter_path(path))
            metadata = path_meta_list[-1]

            if self.version_id_from_meta(metadata) != original_version_id:
                raise jars.VersionIdNotMatchingError(self.storage_id,
                                                     original_version_id)
            parent_meta = path_meta_list[-2]
            drive_id, parent_id = self.api.extract_ids(parent_meta)
        else:

            # Is the relevant information in the model ?
            try:
                parent_node = self.model.get_node(parent_path)
                drive_id = parent_node.props['_drive_id']
                parent_id = parent_node.props['_id']
            except KeyError:
                # The information is not in the model, try the api.
                parent_meta_list = list(self.api.iter_dir_safe(parent_path))

                # The last meta in the list is the parent
                parent_meta = parent_meta_list[-1]

                drive_id, parent_id = self.api.extract_ids(parent_meta)

        response = self.api.upload(drive_id=drive_id,
                                   parent_id=parent_id,
                                   filename=filename,
                                   file_obj=file_obj,
                                   size=size)
        return self.version_id_from_meta(response.json())

    @classmethod
    # pylint: disable=arguments-differ
    def _oauth_get_unique_id(cls, oauth_session, api_root=ONEDRIVE_PRIVATE_API_URL):
        """Return unique id for this account

        This will be called to get a unique identifier for the storage, the same
        identifier must be used, when the share lists are exposed.
        """

        url = urllib.parse.urljoin(api_root, 'drive')
        drive = oauth_session.get(url)
        drive.raise_for_status()
        user_info = drive.json()
        return user_info['owner']['user']['id']
    # pylint: enable=arguments-differ

    def get_shared_folders(self):
        """ Returns a list of :class:`jars.SharedFolder`

        XX: This should be handled by the baseclass, since it does not make any
        calls itself, but extracts the information from the self.model.
        """
        shared_folders = []
        shared_folders_nodes = [node for node in self.model
                                if node.props.get('shared') is True and
                                node.parent.props.get('shared', False) is False]

        # The nodes of which we are the owner and are shareing
        for node in shared_folders_nodes:
            sp_user_ids = node.props['_shared_with']
            sp_user_ids.add(self.drive_id)

            shared_folders.append(SharedFolder(path=node.path,
                                               share_id=node.props['share_id'],
                                               sp_user_ids=sp_user_ids))

        # The nodes which other users have shared with us.
        # It is not possible to get permissions information for share_roots.
        # Therefore the sp_user_ids only contain the id of this account.
        for node in iter_share_roots(self.model):
            shared_folders.append(SharedFolder(path=node.path,
                                               share_id=node.props['share_id'],
                                               sp_user_ids={self.drive_id}))
        logger.info('+++ shared_folders: %s', shared_folders)
        return shared_folders

    def create_user_name(self):
        """Return a username for OneDrive.

        In this case the username will be the displayName, obtained using
        https://dev.onedrive.com/drives/default.htm
        """
        display_name = self.api.get(endpoint='drive').json()['owner']['user']['displayName']
        if display_name == '':
            return 'User id: {}'.format(self.api.get(endpoint='drive').json()['owner']['user']
                                                                             ['id'])
        return display_name
