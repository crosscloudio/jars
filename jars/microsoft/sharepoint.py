"""This module implenents a storage for Microsoft Sharepoint.

Note:
I am trying a few new things in the module.
- Type hinting (In certain places I think it might be quite usefull)
    - https://www.youtube.com/watch?v=7ZbwZgrXnwY
- Numpy type docstrings (I find them the most readable.)
   - http://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_numpy.html#example-numpy

All of these are open for discussion, and can be removed/reverted prior to merge
if so required. The intention of bot of these is to make the code more readable.

I am also trying to extract the logic of add by id to be more reausable in future.
"""
# required for typehinting for now.
# pylint: disable=bad-whitespace
import sys
import contextlib
import copy
import json
import logging
import urllib
from collections import Counter
from enum import Enum

import dateutil
import requests
from requests import HTTPError
from requests_ntlm import HttpNtlmAuth

import bushn
import jars
from jars import BasicStorage

logger = logging.getLogger(__name__)

CHANGE_QUERY = {'query': {'__metadata': {'type': 'SP.ChangeQuery'},
                          'Update': 'true',
                          'Add': 'true',
                          'Item': 'true',
                          'DeleteObject': 'true',
                          'Move': 'true',
                          'Rename': 'true',
                          'File': 'true',
                          'Folder': 'true'}}
"""This query is required to request changes from a sharepoint server."""


class ChangeType(Enum):
    """Interpret the changetype as defined in the documentation:

    Full Documentation at:
    https://msdn.microsoft.com/en-us/library/microsoft.sharepoint.client.changetype.aspx
    """
    NO_CHANGE = 0
    ADD = 1
    UPDATE = 2
    DELETE_OBJECT = 3
    RENAME = 4


# pylint: disable=too-many-arguments
def add_merge_set(merge_set, key='_id', node=None, storage_id=None, event_sink=None,
                  emit_events=False):
    """Wrap `node.add_merge_set_with_id` in all the event emiting code.

    Parameters
    ----------
    merge_set : list
        A list of `Merge`s to be applied.

    key : str, optional
        The key which is used to match nodes with their parents.

    node: bushn.Node
        The root node of the tree to work on.

    storage_id: str
        Name of the storage in the syncengine.

    event_sink: function
        A function which to pass each event.
        ie. `my_task_list.append`

    emit_events: bool
        wether or not these events should be issued.

    Returns
    -------
    None
    """
    adapter = jars.TreeToSyncEngineEngineAdapter(node=node,
                                                 sync_engine=event_sink,
                                                 storage_id=storage_id,)

    logger.info('Merging %d changes', len(merge_set))
    logger.debug('+++ model pre update: \n%s\n +++', bushn.tree_to_str(node, prop_key=key))

    with contextlib.ExitStack() as stack:
        if emit_events:
            stack.enter_context(adapter)

        left_overs = node.add_merge_set_with_id(merge_set, key)
        if left_overs:
            logger.critical("There are %s merges left over", len(left_overs))
            for merge in left_overs:
                logger.info(merge)

    logger.debug('+++ model post update: \n%s\n +++', bushn.tree_to_str(node, prop_key=key))


def iter_sub_path(path: list):
    """Split list of directories into paths needed to create the consecutive path.

    Parameters
    ----------
    path: list
        list of strings.

    Returns
    -------
    Iterator of strings.

    Example
    -------
    >>> sub_paths = iter_sub_path(['one', 'two', 'three'])
    >>> next(sub_paths)
    ['one']
    >>> next(sub_paths)
    ['one', 'two']
    >>> next(sub_paths)
    ['one', 'two', 'three']
    """
    sub_path = []
    for dir_name in path:
        sub_path.append(dir_name)
        yield sub_path


def version_id_from_meta(item_meta):
    """Return the version id from the meta dict"""
    if item_meta['odata.type'] == 'SP.Folder':
        return jars.IS_DIR
    else:
        return item_meta['ETag']

def get_headers(data, storage):
    """Return headers required to make post requests to sharepoint.

    Post requests to the sharepoint api require
        - X-RequestDigest for authentication.
        - Content-Type to specify in which format the data is being sent.
        - Content-Length to specify the length of the data which is being posted.

    Parameters
    ----------
    data: dict
        The post data.

    storage: `Sharepoint` instance
        Required to call `form_digest_value` on.

    Returns
    -------
    Dict with the relevant values set.
    """
    return {'X-RequestDigest': storage.form_digest_value(),
            'Content-Type': "application/json;odata=verbose",
            'Content-Length': str(len(json.dumps(data)))
            }


def item_to_props(item: dict, list_id: str) -> dict:
    """Convert a dictianary returned from api into the props needed for the tree.

    Parameters
    ----------
    item: dict
        file or folder metadata returned from the sharepoint server.

    list_id: str
        list_id needed

    Returns
    -------
    dict

    Example
    -------
    >>> source_item = {'File':
    ...                 {'Name': 'myfile.txt',
    ...                  'Length': 12,
    ...                  'ETag': '>>_etag_<<',
    ...                  'TimeLastModified': '2017-07-20T08:25:34Z',
    ...                  'UniqueId': 99,
    ...                  },
    ...                  'Id': 12341}
    >>> name, props = item_to_props(source_item)
    >>> name
    'myfile.txt'
    >>> props['_list_id']
    '1887f055-7dcd-49dc-9bed-04fecf93452f:12341'
    >>> props['version_id']
    '>>_etag_<<'
    >>> props['shared']
    False
    >>> props['is_dir']
    False
    >>> props['_id']
    99

    etc...
    """
    is_dir = 'Folder' in item
    item_props = item['Folder'] if is_dir else item['File']
    name = item_props['Name']

    size = 0 if is_dir else int(item_props['Length'])
    version_id = jars.IS_DIR if is_dir else item_props['ETag']
    last_mod = dateutil.parser.parse(item_props['TimeLastModified'])

    props = {jars.SHARED: False,
             jars.IS_DIR: is_dir,
             jars.SIZE: size,
             jars.MODIFIED_DATE: last_mod,
             jars.VERSION_ID: version_id,
             '_list_id': ':'.join([list_id, str(item['Id'])]),
             '_id': item_props['UniqueId']}
    return name, props


class SharepointAPI:
    """Encapsulate the various calls which can be made to the Sharepoint rest API.

    Each request is set to raise_for_status, which should then be handeled by the caller.

    Some documentation of the api can be found at:
    https://dev.office.com/sharepoint/docs/sp-add-ins/complete-basic-operations-using-sharepoint-rest-endpoints
    """

    def __init__(self, user_name: str, password: str) -> None:
        """Setup the session with the required authentication and headers."""
        session = requests.Session()
        session.auth = HttpNtlmAuth(user_name, password)
        session.headers.update({"accept": "application/json"})
        self.session = session


    def get(self, url: str, headers=None) -> requests.Response:
        """Issue a get request and return the response."""
        response = self.session.get(url, headers=headers)
        logger.debug('GET [%s:%0.2fs] %s', response.status_code,
                     response.elapsed.total_seconds(), response.url[:200])
        response.raise_for_status()
        return response

    def download(self, url: str, headers=None) -> requests.Response:
        """Stream a file from the provided url."""
        response = self.session.get(url, headers=headers, stream=True)
        logger.info('GET [%s:%0.2fs] %s', response.status_code,
                    response.elapsed.total_seconds(), response.url[:200])
        response.raise_for_status()
        return response

    def post(self, url: str, json_data=None, headers=None) -> requests.Response:
        """Issue a post request and return the response."""

        response = self.session.post(url, json=json_data, headers=headers)
        logger.debug('POST [%s:%0.2fs] %s', response.status_code,
                     response.elapsed.total_seconds(), response.url[:200])

        response.raise_for_status()
        return response

    def upload(self, url: str, file_obj, headers=None):
        """Issue a request to upload a file."""
        response = self.session.post(url, data=file_obj.read(), headers=headers)
        response.raise_for_status()
        return response


class SharePointUrls:
    """Convert various parameters into valid sharepoint urls.

    For Doumentation of these Endpoints see:
    https://dev.office.com/sharepoint/docs/sp-add-ins/working-with-folders-and-files-with-rest
    """

    def __init__(self, base_url: str, doc_lib_name='Shared Documents') -> None:
        self.base_url = base_url
        self.doc_lib_name = doc_lib_name

        if 'sites' in base_url:
            prefix = base_url.split('sites/')[1]
            self.site_rel_prefix = '/'.join(['sites', prefix, doc_lib_name])
        else:
            self.site_rel_prefix = doc_lib_name

    def upload(self, parent_path: list, file_name: str) -> str:
        """Create the url needed to upload a file."""
        template = self.server_relative_folder(parent_path)
        template += "/Files/add(url='{file_name}',overwrite=true)"
        return template.format(file_name=file_name)

    def download(self, path: list) -> str:
        """Return url needed to read a file."""
        url = self.base_url + "/{doc_lib_name}/{path}"
        return url.format(doc_lib_name=self.doc_lib_name, path='/'.join(path))

    def files(self, path: list) -> str:
        """Return url needed to list files in the path"""
        return self.server_relative(path) + '/files'

    def folders(self, path: list) -> str:
        """Return url needed to list folders in the path"""
        return self.server_relative(path) + '/folders'

    def server_relative(self, path: list) -> str:
        """Return the url needed to address a file via its path."""
        template = self.base_url + \
            "/_api/web/GetFileByServerRelativeUrl('/{site_rel_prefix}/{server_path}')"
        url = template.format(site_rel_prefix=self.site_rel_prefix, server_path='/'.join(path))
        return url

    def server_relative_folder(self, path: list) -> str:
        """Return the url needed to address a folder via its path."""
        url = self.base_url + \
            "/_api/web/GetFolderByServerRelativeUrl('/{site_rel_prefix}/{path}')"
        url = url.format(site_rel_prefix=self.site_rel_prefix, path='/'.join(path))
        return url

    def contextinfo(self):
        """Return the url required to get the context info of the site."""
        return self.base_url + '/_api/contextinfo'

    def move_folder(self, source:str, target:str) -> str:
        """Return the url required to move a folder to a new path."""
        url = self.server_relative_folder(path=source)
        url += "/moveto(newUrl='/{site_rel_prefix}/{target}')"
        return url.format(site_rel_prefix=self.site_rel_prefix, target='/'.join(target))

    def move_file(self, source:str, target:str) -> str:
        """Return  url required to move a file to a new path."""
        url = self.server_relative(path=source)
        url += "/moveto(newurl='/{site_rel_prefix}/{target}',flags=1)"
        return url.format(site_rel_prefix=self.site_rel_prefix, target='/'.join(target))

    def list_folder_file(self, guid:str) -> str:
        """Return url required to list all files and folders in a site."""
        url = self.base_url + "/_api/Web/Lists(guid'{}')/items?$expand=Folder,File"
        return url.format(guid)

    def list_item_meta(self, list_id:str, item_id:str ) -> str:
        """Return the url required to get the matadata of a list item."""
        url = self.base_url + "/_api/web/Lists(guid'{list_id}')/Items('{item_id}')/"
        url += '?$expand=File,Folder'
        return url.format(list_id=list_id, item_id=item_id)

    def parent_meta(self, item_id:str) -> str:
        """Return the url required to get the metadata of a items parent."""
        url = self.base_url + \
            "/_api/web/GetFolderById('{}')?$select=ParentFolder&$expand=ParentFolder"
        return url.format(item_id)

    def list_id_from_title(self, title):
        """Return the url required to to get the list_id/guid based on the title."""
        url = self.base_url + "/_api/web/Lists/GetByTitle('{title}')/?$select=ID"
        return url.format(title=title)

    def get_site_id(self):
        """Return GUID of the current site."""
        url = self.base_url + "/_api/web/id"
        return url

    def get_site_title(self):
        """Return GUID of the current site."""
        url = self.base_url + "/_api/web/title"
        return url


class SharePoint(BasicStorage):
    """Sync on self hosted sharepoint servers."""
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-many-public-methods

    storage_name = 'sharepoint'
    storage_display_name = 'SharePoint'

    API_CLASS = SharepointAPI
    URL_BUILDER_CLASS = SharePointUrls

    auth = [BasicStorage.AUTH_CREDENTIALS]
    supports_sharing_link = False

    def __init__(self, event_sink, storage_id, storage_cred_reader, *args, **kwargs):
        # pylint: disable=unused-argument
        self.storage_id = storage_id
        self.event_sink = event_sink
        auth_data = json.loads(storage_cred_reader())
        self.urls = self.URL_BUILDER_CLASS(base_url=auth_data['server'])
        self.api = self.API_CLASS(user_name=auth_data['user_name'],
                                  password=auth_data['password'])
        self.event_poller = self._init_poller()
        self._list_id = None
        self.username = auth_data['user_name']
        super().__init__(event_sink, storage_id)

    @staticmethod
    def authenticate(url, username, password, verify=True, force=False):
        # pylint: disable=arguments-differ
        # pylint: disable=unused-argument
        # writing auth data to keychain
        auth_data = {'server': url, 'user_name': username, 'password': password}
        credentials = json.dumps(auth_data)
        # to get a nice identifier we need to perform a request to fetch the site GUID
        site_id = request_site_id(api=SharepointAPI(user_name=username, password=password),
                                  url=SharePointUrls(base_url=url))
        identifier = prepare_user_unique_id(site_id, username)

        return [], credentials, identifier

    def _get_meta(self, path: list, is_dir=False) -> dict:
        """Get the current meta data of an item on the remote.

        There are two endpoints one for folders and one for files.
        The parameter is_dir cannot be trusted. It is only set if we have it avaliable.
        Therefore if the call to either the folder or the file endpoint fails,
        the other endpoint must be tried.
        """
        urls = [self.urls.server_relative(path),
                self.urls.server_relative_folder(path)]
        if is_dir:
            # If we think it is a dir, try folder url first.
            urls.reverse()

        for url in urls:
            try:
                meta = self.api.get(url).json()
                break
            except HTTPError as error:
                if error.response.status_code == 500:
                    meta = None
                    continue
                else:
                    raise error

        if meta is None:
            raise FileNotFoundError

        return meta

    def _verify_version_id(self, path, version_id):
        is_dir = version_id == jars.IS_DIR
        current_meta = self._get_meta(path, is_dir=is_dir)

        if version_id == jars.FOLDER_VERSION_ID:
            return current_meta

        current_version_id = version_id_from_meta(current_meta)
        if current_version_id != version_id:
            raise jars.VersionIdNotMatchingError(storage_id=self.storage_id,
                                                 version_a=version_id,
                                                 version_b=current_version_id)
        return current_meta

    def update_internal_model(self):
        """Call apply_changes on internal model."""

        with self.model.lock:
            self.fetch_and_apply_changes(self.model)
            logger.info('Update on internal model finished.')

    def update(self):
        """Updates storage and sets state for upcoming events.

        Note: lock the model while calling get_tree if needed, and update_internal_model.
        """
        logger.debug('Update called.')
        with self.model.lock:
            if jars.CURSOR not in self.model.props:
                self.model = self._get_tree()
            self.update_internal_model()

    def fetch_and_apply_changes(self, model):
        """Call the getchanges endpoint.

        And apply the approriate changes.
        """
        # pylint: disable=too-many-locals
        if jars.CURSOR not in model.props:
            logger.info("Failed to apply changes. The model has no cursor. "
                        "Call update first.")
            return

        data = copy.deepcopy(CHANGE_QUERY)
        data['query']['ChangeTokenStart'] = model.props[jars.CURSOR]

        url = self.urls.base_url + "/_api/web/getchanges"
        resp = self.api.post(url, headers=get_headers(data, self), json_data=data)
        changes = resp.json()['value']

        if changes:
            # log what we plan to change
            change_types = [ChangeType(c['ChangeType']) for c in changes]
            logger.info('Processing %s changes.', len(change_types))
            logger.info(Counter(change_types))
        merge_set = []
        for item in changes:
            change_type = ChangeType(item['ChangeType'])
            # logger.info('change_type: %s', change_type)

            if change_type is ChangeType.ADD \
                    or change_type is ChangeType.UPDATE \
                    or change_type is ChangeType.RENAME:
                # first we need to get the metadata.
                url = self.urls.list_item_meta(list_id=item['ListId'],
                                               item_id=item['ItemId'])
                response = self.api.get(url)
                name, props = item_to_props(response.json(), list_id=self.list_id)
                merge_set.append(bushn.NodeChange(action='UPSERT',
                                                  parent_id=self.get_parent_id(props['_id']),
                                                  name=name,
                                                  props=props))
            elif change_type is ChangeType.DELETE_OBJECT:
                list_id = ':'.join([item['ListId'], str(item['ItemId'])])
                node = model.index['_list_id'].get(list_id)
                if node:
                    merge_set.append(bushn.NodeChange(action='DELETE',
                                                      parent_id=None,
                                                      name=None,
                                                      props=node.props))
                else:
                    logger.info('Failed to delete ')
            else:
                logger.critical('Item not processed: %s', item)

            model.props[jars.CURSOR] = item['ChangeToken']
            logger.info('New change token set: %s', item['ChangeToken'])

        add_merge_set(merge_set, key='_id', node=model, storage_id=self.storage_id,
                      event_sink=self.event_sink, emit_events=True)

    def get_parent_id(self, item_id):
        """Return the id of the parent folder of an item, based on its item_id.

        Parameters
        ----------
        item_id: str
            id used to uniquely identify a item in the tree.
        """
        url = self.urls.parent_meta(item_id=item_id)
        response = self.api.get(url).json()
        return response['ParentFolder']['UniqueId']

    def start_events(self):
        """Starts the delivery of events.

        See :py:class:~`BasicStorage` for full documentation.
        """
        logger.debug('Starting events called.')

        if (self.event_poller and not self.event_poller.is_alive()) \
                or not self.event_poller:
            # recreate poller instance
            self.event_poller = self._init_poller()
            logger.info('Events started.')
            self.event_poller.start()

    def _init_poller(self):
        def set_offline(value):
            """Set the offline state."""
            self.offline = value

        # creating poller getting events from the storage
        return jars.PollingScheduler(interval=10,
                                     target=self.update_internal_model,
                                     offline_callback=set_offline)

    def stop_events(self, join=False):
        """Stop the delivery of events.

        :param join: if true this methods should blocks and joins executing thread.

        See :py:class:~`BasicStorage` for full documentation.
        """
        logger.info('stopping events')
        self.event_poller.stop(join=join, timeout=20)

    def make_dir(self, path):
        """Create a directory on the storage, implicitly creates all parents. No
        exceptions are thrown if the parent already exists.

        :param path: A path as list of strings.
        :returns: returns the folders version id

        See :py:class:~`BasicStorage` for full documentation.
        """
        url = self.urls.base_url + '/_api/web/folders'
        for sub_path in iter_sub_path(path):
            sub_path = [self.urls.doc_lib_name] + sub_path

            meta = {'__metadata': {'type': 'SP.Folder'},
                    'ServerRelativeUrl': '/'.join(sub_path)}

            headers = {'X-RequestDigest': self.form_digest_value(),
                       'Content-Type': "application/json;odata=verbose",
                       'Content-Length': str(len(json.dumps(meta)))}

            self.api.post(url, json_data=meta, headers=headers)

        return jars.IS_DIR

    def open_read(self, path, expected_version_id=None):
        """Download the file to the filesystem.

        :param path: a path represented by a list of strings
        :param expected_version_id
        :returns: file like object representing of the given file on storage.

        See :py:class:~`BasicStorage` for full documentation.
        """
        url = self.urls.download(path)
        headers = {
            'If-Match': expected_version_id
        }
        try:
            response = self.api.download(url, headers=headers)
        except HTTPError as error:
            if error.response.status_code == 404:
                raise FileNotFoundError

            elif error.response.status_code == 412:
                raise jars.VersionIdNotMatchingError()
            else:
                raise error
        return response.raw

    def write(self, path, file_obj, original_version_id=None, size=0):
        """Write a file to the given storage.

        :param size: size of the file being written
        :param original_version_id: the known version id of the metadata.
        :param file_obj: The file object where the file is read from
        :param path: the path is a list of strings

        See :py:class:~`BasicStorage` for full documentation.
        """
        #TODO: large upload.
        # seperate path into filename and parent_path
        file_name = path[-1]
        parent_path = path[:-1]
        if original_version_id is not None:
            self._verify_version_id(path, original_version_id)

        url = self.urls.upload(parent_path=parent_path, file_name=file_name)
        self.make_dir(parent_path)
        headers = {'X-RequestDigest': self.form_digest_value(),
                   'Content-Length': str(size)}

        item_meta = self.api.upload(url, file_obj, headers=headers).json()

        return version_id_from_meta(item_meta)

    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """Move a file or folder from one path to another.

        :param source: a path represented by a list of strings
        :param target: a path represented by a list of strings
        :param expected_source_vid: the expected version id of the source
        :param expected_target_vid: if the target already exists, this is the version id
        of the file to be replaced

        based on:
        https://sharepoint.stackexchange.com/questions/152936/rest-call-to-move-a-file-folder-to-another-location

        See :py:class:~`BasicStorage` for full documentation.
        """
        if expected_source_vid is not None:
            self._verify_version_id(path=source, version_id=expected_source_vid)

        if expected_target_vid is not None:
            self._verify_version_id(path=target, version_id=expected_target_vid)

        if expected_source_vid == jars.IS_DIR:
            url = self.urls.move_folder(source=source, target=target)
        else:
            url = self.urls.move_file(source=source, target=target)
        # Ensure that destination folder is avaliable.
        self.make_dir(target[:-1])

        headers = {  # 'If-Match': expected_target_vid,
            'X-RequestDigest': self.form_digest_value()}
        try:
            _ = self.api.post(url, headers=headers)
        except HTTPError as error:
            if error.response.status_code == 500:
                raise FileNotFoundError
            else:
                raise error

        return version_id_from_meta(self._get_meta(target))

    def form_digest_value(self):
        """Return a FormDigestValue required for each post request."""
        url = self.urls.contextinfo()
        contextinfo = self.api.post(url).json()

        # TODO: reuse the FormDigestValue if possible
        # self._form_digest_timeout_seconds = contextinfo['FormDigestTimeoutSeconds']
        return contextinfo['FormDigestValue']

    def delete(self, path, original_version_id):
        """Delete a file or folder on the remote storage

        :param path: a list of strings
        :param original_version_id: the known version id of the metadata.

        See :py:class:~`BasicStorage` for full documentation.
        """
        logger.info('delete: %s', path)
        current_meta = self._verify_version_id(path=path, version_id=original_version_id)

        if current_meta is None:
            raise FileNotFoundError

        if original_version_id == jars.IS_DIR:

            url = self.urls.server_relative_folder(path)
            etag = '*'
        else:
            url = self.urls.server_relative(path)
            etag = original_version_id

        response = self.api.post(url, headers={'If-Match': etag,
                                               'X-RequestDigest': self.form_digest_value(),
                                               'X-HTTP-Method': "DELETE"})

        if response.status_code == 500:
            response_json = response.json()
            odata_error_code = response_json['odata.error']['code']
            if odata_error_code == '-2146232832, Microsoft.SharePoint.SPException':
                raise FileNotFoundError

    def get_tree_children(self, path):
        """Get the children of a certain path.

        Note: Due to the following problems. multiple requests are needed.

        - The '/items?$expand=Folder,File' endpoint returns all items in the tree.
        - The 'GetFolderByServerRelativeUrl()' endpoint return an extra 'Forms' directory.
        - The '/folders/?$filter=ListItemAllFields+ne+null' does not fail if the dir does
        not exist.

        Parameters
        ----------
        path: list
            The elements of the path.

        Returns
        -------
        Iterable of tuple of path and prop dictionaries

        See :py:class:~`BasicStorage` for full documentation.
        """
        url = self.urls.server_relative_folder(path)

        # We first need to call this url, because the response from the following url
        # does not differentiate wether a folder exists or not.
        try:
            self.api.get(url)
        except HTTPError as error:
            if error.response.status_code == 500:
                raise FileNotFoundError(error.response.text)
            else:
                raise error

        url += "/folders/?$filter=ListItemAllFields+ne+null"
        response = self.api.get(url)

        for item in response.json()['value']:
            node_properties = {jars.IS_DIR: True}
            yield (item['Name'], node_properties)

    def get_latest_change_token(self):
        """Return the latest changetoken.

        In order to get the latest change tonken, we page through all changes, untill
        no change token can be found anymore.
        """
        # get the changelog and save token prior to getting current state.
        url = self.urls.base_url + "/_api/web/getchanges"
        data = copy.deepcopy(CHANGE_QUERY)
        change_token = ''
        while True:
            try:
                resp = self.api.post(url, headers=get_headers(data, self), json_data=data)
                changes = resp.json()['value']
                change_token = changes[-1]['ChangeToken']
                data['query']['ChangeTokenStart'] = change_token
            except (IndexError, KeyError):
                # found the last changetoken.
                break
        return change_token

    def get_tree(self, cached=False):
        """Return either a copy of the cached tree or a new tree from the remote.

        In both cases, the tree is filtered using the filtertree.

        Parameters
        ----------
        cached: bool
            Wether to use the internal model or get a fresh model from the remote.
        """
        if cached:
            model = copy.deepcopy(self.model)
        else:
            model = self._get_tree()

        return jars.utils.filter_tree_by_path(model, self.filter_tree)

    @property
    def list_id(self):
        """Return the id needed to call the list"""
        if not self._list_id:
            url = self.urls.list_id_from_title(title='Documents')
            self._list_id = self.api.get(url).json()['Id']
        return self._list_id


    def _get_tree(self):
        root = self._create_root_node()
        root.props[jars.CURSOR] = self.get_latest_change_token()

        url = self.urls.list_folder_file(guid=self.list_id)
        response = self.api.get(url)
        merge_set = []
        for item in response.json().get('value', []):
            is_dir = 'Folder' in item
            if is_dir:
                item_props = item['Folder']
            else:
                item_props = item['File']

            size = 0 if is_dir else int(item_props['Length'])
            version_id = jars.IS_DIR if is_dir else item_props['ETag']
            last_mod = dateutil.parser.parse(item_props['TimeLastModified'])

            props = {jars.SHARED: False,
                     jars.IS_DIR: is_dir,
                     jars.SIZE: size,
                     jars.MODIFIED_DATE: last_mod,
                     jars.VERSION_ID: version_id,
                     '_list_id': ':'.join([self.list_id, str(item['Id'])]),
                     '_id': item_props['UniqueId']}
            # logger.info('### props[_id]: %s', props['_id'])
            merge_set.append(bushn.NodeChange(action='UPSERT',
                                              parent_id=self.get_parent_id(props['_id']),
                                              name=item_props['Name'],
                                              props = props))

        root.add_merge_set_with_id(merge_set, key='_id')
        return root

    def check_available(self):
        """Check if the storage is available."""
        raise NotImplementedError

    def clear_model(self):
        """Reset the internal model of the storage."""
        self.model = self._create_root_node()
        logger.info('model was cleared')

    def _create_root_node(self):
        root = bushn.IndexingNode(name=None, indexes=['_id', '_list_id'])

        root.props[jars.METRICS] = self.get_storage_metrics()

        root.props['_id'] = self.root_id

        logger.info('New root created: %s', root)
        return root

    @property
    def root_id(self):
        """Return the Unique Id of the root."""
        path = []
        url = self.urls.server_relative_folder(path)
        response = self.api.get(url)
        return response.json()['UniqueId']


    def get_storage_metrics(self):
        """Call the usage endpoint and calculate the required metrics.

        Based on the documentation of SP.UsageInfo object
        https://msdn.microsoft.com/en-us/library/office/jj245404.aspx
        """
        url = self.urls.base_url + '/_api/site/usage'
        response_json = self.api.get(url).json()

        storage_used = float(response_json['Storage'])
        logger.info('Storage_used: %s', storage_used)
        percentage_used = float(response_json['StoragePercentageUsed'])
        logger.info('Percentage_used: %s', percentage_used)
        try:
            total_space = storage_used/percentage_used
            free_space = total_space - storage_used
        except ZeroDivisionError:
            # no quota set
            free_space = sys.maxsize
            total_space = sys.maxsize


        return jars.StorageMetrics(self.storage_id,
                                   free_space=free_space,
                                   total_space=total_space)


    def create_user_name(self):
        """Return a username with sharepoint structure.

        The structure of the username should be 'name'@'url'.
        """
        response = self.api.get(self.urls.get_site_title()).json()
        domain = urllib.parse.urlparse(self.urls.base_url).netloc
        suffix = domain + '/' + response['value']
        return prepare_user_unique_id(suffix, self.username)


# Comment this function, we might need it in the future
def request_site_id(api, url):
    """Return the id of the site."""
    url = url.get_site_id()
    response = api.get(url).json()
    return response['value']


def prepare_user_unique_id(suffix, user_id=''):
    """Return standard user_id structure for storages with no user unique_id.

    user@url
    """
    # TODO: Apparently it might be possible to change the site name for sharepoint, thus
    # changing the url and causing problems. After investigating and reaching a decision on
    # how to handle this in cause it really is a problem we should pretty this identifiers up

    # This was used to trim the url to the base, with sharepoint we need the whole path.
    # Needs further testing to ensure that owncloud doesn't break due to this.
    # domain = urllib.parse.urlparse(url).netloc

    # its important that this is casefold, as users from the server
    # are returned that way for shares
    return '{}@{}'.format(user_id, suffix).casefold()
