"""Wrap the microsoft graph api in order to interact with it in a storage."""
import logging
import json
from requests_oauthlib import OAuth2Session

import jars
from jars.streaming_utils import Fragmenter
from .onedrive import raise_for_status

logger = logging.getLogger(__name__)

UPLOAD_FRAGMENT_SIZE = 1024 * 320 * 6
"""This is used for fragmenting uploads, according to the`OneDrive documentation
<https://dev.onedrive.com/items/upload_large_files.htm#best-practices>`_ this
should be a multiple of 320 KiB
"""
# pylint: disable=unused-argument
# pylint: disable=super-init-not-called
# these three pylint errors are supressed, because storage and API are still very
#  much intertwined, and need to be refactored.


class OneDriveIterator:
    """Pagination helper.

    see https://dev.onedrive.com/items/list.htm
    """

    def __init__(self, api, url, params=None):
        """Initialise a OneDriveIterator."""
        self.api = api
        self.url = url
        self.last_response = None
        self.params = params or {}

    def __iter__(self):
        """Iterate over each next_link, yielding the contained items.

        last_response is set as an attribute in order to extract delta_token/urls once
        the iterator has been exaused.
        """
        next_link = self.url

        while True:
            response_json = self.api.get(url=next_link, params=self.params).json()

            for item in response_json['value']:
                yield item

            self.last_response = response_json

            if '@odata.nextLink' in response_json:
                next_link = response_json['@odata.nextLink']
            else:
                break


class UrlBuilder:
    """Build urls for MicrosoftGraphApi."""

    def __init__(self, base_url='https://graph.microsoft.com'):
        """Initialise UrlBuilder with a base url."""
        self.base_url = base_url

    def build(self, endpoint='me/drive/root', version='v1.0',):
        """Build a url for MicrosoftGraphApi consumption."""
        return '/'.join([self.base_url, version, endpoint])

    def root_info(self, group_id=None):
        """Return a url which can be used to get information about the root of a drive."""
        if group_id is None:
            endpoint = 'me/drive/root'
        else:
            endpoint = 'groups/{group_id}/drive/root'.format(group_id=group_id)
        return self.build(endpoint=endpoint)

    def drive_info(self, group_id=None):
        """Return a url which can be used to get informations such as storage metrics."""
        if group_id is None:
            endpoint = 'me/drive'
        else:
            endpoint = 'groups/{group_id}/drive'.format(group_id=group_id)

        return self.build(endpoint=endpoint)

    def path_meta(self, path, group_id=None):
        """Return a url which can be called to get the meta of an item at the path."""
        if group_id is None:
            endpoint = 'me/drive/root:/{path}:/'.format(path=path)
        else:
            endpoint = 'groups/{group_id}/drive/root:/{path}:/'.format(path=path,
                                                                       group_id=group_id)
        return self.build(endpoint=endpoint)

    def upload(self, parent_path=None, parent_id=None, filename=None, group_id=None):
        """Return a url for an upload.

        documented at:
        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_uploadcontent

        The options are:
        - PUT /me/drive/items/{parent-id}:/{filename}:/content
        - PUT /me/drive/root:/{parent-path}/{filename}:/content
        - PUT /me/drive/items/{parent-id}/children/{filename}/content
        - PUT /groups/{id}/drive/items/{parent-id}/children/{filename}/content
        """
        if group_id is not None and parent_id is not None:
            endpoint = 'groups/{group_id}/drive/items/{parent_id}/children/{filename}/content'
            endpoint = endpoint.format(group_id=group_id, parent_id=parent_id, filename=filename)
        elif group_id:
            # assert parent_id, 'parent_id is required for group upload'
            endpoint = 'groups/{group_id}/drive/items/{parent_id}/children/{filename}/content'
            endpoint = endpoint.format(group_id=group_id, parent_id=parent_id, filename=filename)
        elif parent_path:
            endpoint = 'me/drive/root:/{parent_path}/{filename}:/content'
            endpoint = endpoint.format(parent_path=parent_path, filename=filename)
        elif parent_id:
            endpoint = 'me/drive/items/{parent_id}/children/{filename}/content'
            endpoint = endpoint.format(parent_id=parent_id, filename=filename)
        else:
            # we only have a file_name -> write to root
            endpoint = 'me/drive/root:/{filename}:/content'.format(filename=filename)
        return self.build(endpoint=endpoint)

    def upload_session(self, path, group_id=None):
        """Return a url required to initate an upload session.

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_createuploadsession

        documented options:
        POST /me/drive/root:/{path-to-item}:/createUploadSession
        POST /me/drive/items/{parent-item-id}:/{filename}:/createUploadSession
        """
        if group_id is None:
            endpoint = 'me/drive/root:/{path}:/createUploadSession'.format(path=path)
        else:
            endpoint = 'groups/{group_id}/drive/root:/{path}:/createUploadSession'
            endpoint = endpoint.format(path=path, group_id=group_id)
        return self.build(endpoint=endpoint)

    def download(self, path, group_id=None):
        """Return a url required to download a item from the provided path.

        Documented at:
        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_downloadcontent

        documented options:
        GET /me/drive/root:/{item-path}:/content
        GET /me/drive/items/{item-id}/content
        GET /drives/items/{item-id}/content
        GET /groups/{group-id}/drive/items/{item-id}/content
        """
        if group_id is None:
            endpoint = 'me/drive/root:/{item_path}:/content'.format(item_path=path)
        else:
            endpoint = 'groups/{group_id}/drive/root:/{item_path}:/content'
            endpoint = endpoint.format(group_id=group_id, item_path=path)

        return self.build(endpoint=endpoint)

    def children(self, path=None, parent_meta=None, group_id=None):
        """Return a url required to iterate the children of an item.

        Documented at:
        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_list_children

        documented options:
        GET /me/drive/root/children
        GET /me/drive/items/{item-id}/children
        GET /me/drive/root:/{item-path}:/children
        GET /drives/{drive-id}/items/{item-id}/children
        GET /groups/{group-id}/drive/items/{item-id}
        """
        if group_id is None:
            if parent_meta:
                endpoint = 'me/drive/items/{item_id}/children'.format(item_id=parent_meta['id'])
            elif path is None:
                # root
                endpoint = 'me/drive/root/children'
        else:
            if parent_meta:
                endpoint = 'groups/{group_id}/drive/items/{item_id}/children'
                endpoint = endpoint.format(group_id=group_id, item_id=parent_meta['id'])
            elif path is None:
                # root
                endpoint = 'groups/{group_id}/drive/root/children'.format(group_id=group_id)

        return self.build(endpoint=endpoint)

    def delete(self, path, item_meta=None, group_id=None):
        """Return a url required to delete a item.

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_delete

        documented options:
        DELETE /me/drive/items/{item-id}
        DELETE /me/drive/root:/{item-path}
        DELETE /drives/{drive-id}/items/{item-id}
        DELETE /groups/{group-id}/drive/items/{item-id}
        """
        if group_id is None:
            endpoint = 'me/drive/root:/{item_path}'.format(item_path=path)
        else:
            endpoint = 'groups/{group_id}/drive/root:/{item_path}'.format(item_path=path,
                                                                          group_id=group_id)
        return self.build(endpoint=endpoint)

    def delta(self, group_id=None):
        """Return a url required to query a delta on eiter the root or root of a group.

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_delta

        documented options:
        GET /me/drive/root/delta
        GET /drives/{drive-id}/root/delta
        GET /groups/{group-id}/drive/root/delta
        """
        if group_id is None:
            endpoint = 'me/drive/root/delta'
        else:
            endpoint = 'groups/{group_id}/drive/root/delta'.format(group_id=group_id)
        return self.build(endpoint=endpoint)

    def new_dir(self, parent_dir_meta=None, group_id=None):
        """Return a url required to create a new directory.

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_post_children

        documented options:
        POST /me/drive/root/children
        POST /me/drive/items/{parent-item-id}/children
        POST /drives/{drive-id}/items/{parent-item-id}/children
        POST /groups/{group-id}/drive/items/{parent-item-id}/children
        """
        if group_id is None:
            if parent_dir_meta:
                endpoint = 'me/drive/items/{parent_item_id}/children'
                endpoint = endpoint.format(parent_item_id=parent_dir_meta['id'])
            else:
                endpoint = 'me/drive/root/children'
        else:
            if parent_dir_meta:
                endpoint = 'groups/{group_id}/drive/items/{parent_item_id}/children'
                endpoint = endpoint.format(parent_item_id=parent_dir_meta['id'],
                                           group_id=group_id)
            else:
                endpoint = 'groups/{group_id}/drive/root/children'.format(group_id=group_id)
        return self.build(endpoint=endpoint)

    def patch(self, item_meta, group_id=None):
        """Return a url required to patch a certain item.

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_move

        documented options:
        PATCH /me/drive/items/{item-id}
        PATCH /me/drive/root:/{item-path}
        PATCH /drives/{drive-id}/items/{item-id}
        PATCH /groups/{group-id}/drive/{item-id}
        """
        if group_id is None:
            endpoint = 'me/drive/items/{item_id}/'.format(item_id=item_meta['id'])
        else:
            endpoint = 'groups/{group_id}/drive/items/{item_id}/'
            endpoint = endpoint.format(item_id=item_meta['id'], group_id=group_id)
        return self.build(endpoint=endpoint)


class MicrosoftGraphApi(jars.OAuthApi):
    """Wrapper around the Microsoft Graph Api which is decribed in the docs.

    https://developer.microsoft.com/en-us/graph/docs
    """

    # registered at
    # https://apps.dev.microsoft.com/
    # rough_animal ids for testing.
    # registered by crosscloudci.101@crosscloudci.onmicrosoft.com
    # client_id = 'd16b89a9-4fc0-4eeb-8091-94275885b93f'
    # client_secret = 'fWZJ54kSEU7rOnyb8dm98VR'
    # registered by christoph@crosscloud.me
    client_id = 'CLIENT_ID'
    client_secret = 'CLIENT_SECRET'

    redirect_uri = 'http://localhost:9324'
    authorization_base_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

    scope = ['files.read',
             'files.read.all',
             'files.read.selected',
             'files.readwrite',
             'files.readwrite.all',
             'offline_access',
             #  'profile',
             'sites.read.all',
             'user.read',
             'user.readbasic.all',
             'sites.readwrite.all']

    def __init__(self, *args,
                 storage_cred_reader=None,
                 storage_cred_writer=None,
                 session=None, **kwargs):
        """Initialize the session if not provided, and setup drive_id."""
        if session is None:
            self.session = OAuth2Session(
                client_id=self.client_id,
                token=json.loads(storage_cred_reader()),
                token_updater=lambda token: storage_cred_writer(json.dumps(token)),
                auto_refresh_kwargs={'client_id': self.client_id,
                                     'client_secret': self.client_secret},
                auto_refresh_url=self.token_url)
        else:
            self.session = session

        # save our dirve_id
        self.drive_id = self._oauth_get_unique_id(self.session)

    @classmethod
    def _oauth_get_unique_id(cls, oauth_session):
        """Return unique id for this account.

        This will be called to get a unique identifier for the storage, the same
        identifier must be used, when the share lists are exposed.
        """
        url = UrlBuilder().build(endpoint='me')
        return oauth_session.get(url).json()['id']

    def get(self, url=None, status_check=raise_for_status, **kwargs):
        """Make a get request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        This is the method all other get_methods in this class should call.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response prior to returning
                             default to `raise_for_status` function

        :param kwargs: Are passed to the get request.
        """
        try:
            response = self.session.get(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.get() failed to pass unexpected keyword argument requests.')
            raise

        logger.info('GET [%s:%0.2fs] %s', response.status_code,
                    response.elapsed.total_seconds(), response.url[:200])

        # use the status_check function to raise for status or some derivative.
        if callable(status_check):
            status_check(response)

        return response

    def post(self, url=None, status_check=raise_for_status, **kwargs):
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

    def delete(self, url=None, status_check=raise_for_status, **kwargs):
        """Make a delete request to the api.

        If a url is provided, it will be used, otherwise one will be constructed using the
        api_root and the endpoint.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param endpoint: string to urljoin to the api_root to get a full url
        :param status_check: function to call on response, default to `raise_for_function`.
        passing any non callable such as False will skip the check.

        all other kwargs are passed to the delete request.
        """
        try:
            response = self.session.delete(url, **kwargs)
        except TypeError:
            logger.warning(
                'OneDrive.delete() failed to pass unexpected keyword argument requests.')
            raise

        if callable(status_check):
            status_check(response)

        return response

    def put(self, url, file_obj, *args, **kwargs):
        """Upload the file with the simple item upload.

        This is very fast for small files, since it creates the directories implicitly and
        only needs one request

        https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/item_uploadcontent
        """
        response = self.session.put(url, data=file_obj.read(), *args, **kwargs)
        logger.info('PUT [%s:%0.2fs] %s', response.status_code,
                    response.elapsed.total_seconds(), response.url)
        return response

    def patch(self, url=None, status_check=raise_for_status, **kwargs):
        """Make a patch request to the api.

        :param url: the full url unless one is to be created out of api_root and endpoint
        :param status_check: function to call on response, default to `raise_for_function`.
        passing any non callable such as False will skip the check.

        all other kwargs are passed to the patch request.
        """
        try:
            response = self.session.patch(url, **kwargs)
            logger.info('PATCH [%s:%0.2fs] %s', response.status_code,
                        response.elapsed.total_seconds(), response.url)
        except TypeError:
            logger.warning(
                'OneDrive.patch() failed to pass unexpected keyword argument requests.')
            raise

        if callable(status_check):
            status_check(response)

        return response

    def upload_large(self, url, file_obj, size):
        """Upload large files using an uploadsession."""
        session_create_response = self.post(url).json()
        upload_url = session_create_response['uploadUrl']

        fragment_response = None
        for fragment in Fragmenter(file_obj,
                                   fragment_size=UPLOAD_FRAGMENT_SIZE,
                                   file_size=size):

            headers = {'Content-Length': str(fragment.length),
                       'Content-Range': 'bytes {}-{}/{}'.format(fragment.begin,
                                                                fragment.end, size)}

            # TODO: refactor this to use self.put
            fragment_response = self.session.put(upload_url,
                                                 data=fragment.file_obj,
                                                 headers=headers)
            fragment_response.raise_for_status()

        return fragment_response

    def download(self, url):
        """Download a file from a url.

        Note: the header accept-encoding = None must be set, otherwise the reading of the
        encyption header will not work.
        """
        headers = {'accept-encoding': None}
        response = self.get(url, stream=True, headers=headers)
        response.raw.decode_content = True
        return response.raw


class Office365Api(MicrosoftGraphApi):
    """MicrosoftGraphApi for which an admin must authenticate the app for all users.

    Since the scope includes group and user permissions in order to work correctly,
    an admin must autheticate this api by visiting:
    https://login.microsoftonline.com/common/adminconsent?client_id=45e11b8f-e560-4fc1-badf-9ccca8ba62ef
    """

    client_id = 'CLIENT_ID'
    client_secret = 'CLIENT_SECRET'

    scope = ['group.read.all',
             'group.readwrite.all',
             'files.readwrite.all',
             'files.read',
             'files.readwrite',
             'files.read.selected',
             'sites.readwrite.all',
             'files.read.all',
             'user.read',
             'user.readbasic.all',
             'sites.read.all']
