"""Owncloud and NextCloud implementation.

Owncloud uses WebDAV as sync protocol. We are going to extend our webdav implementations
here.
It uses the OCS API for sharing things:
https://doc.owncloud.org/server/7.0/developer_manual/core/ocs-share-api.html

For all the shares related operations it is necesary to use a different API which uses the
following endpoint as a base: 'ocs/v1.php/apps/files_sharing/api/v1/shares', appended to the base
url (i.e. 'https://owncloud.crosscloud.me/ocs/v1.php/apps/files_sharing/api/v1/shares').
Depending on the arguments and extension on the URL different operations will be performed.

To access a specific share is necessary to get append the share_id to the previous url.
'https://owncloud.crosscloud.me/ocs/v1.php/apps/files_sharing/api/v1/shares/<share id>'
an xml with information of this share only will be returned.
"""
import logging
import sys
import urllib.parse
import xml.etree.ElementTree
from collections import namedtuple

import bushn

import jars
import jars.webdav

from . import (METRICS, SHARED, SharedFolder, StorageError, StorageMetrics,
               registered_storages)

logger = logging.getLogger(__name__)

SHARES_INFO = '_shares_info'

# Tuple to containing all the share info for shared paths
ShareInfo = namedtuple('ShareInfo', ['path',
                                     'share_id',
                                     'sp_user_ids',
                                     'share_type'])


class OwnCloud(jars.webdav.Webdav):
    """Implements owncloud spec."""

    # suffix to access the sharing properties in OC
    SHARING_API = 'ocs/v1.php/apps/files_sharing/api/v1/shares'
    WEBDAV_ENDPOINT = 'remote.php/webdav'

    storage_name = 'owncloud'
    storage_display_name = 'OwnCloud'

    # pylint: disable=too-many-arguments

    @staticmethod
    def authenticate(url, username, password, verify=True, force=False):
        """Authenticate the user on the server."""
        # sanitizing url for owncloud
        url = prepare_url(url, OwnCloud.WEBDAV_ENDPOINT)

        # check uniqueness of account
        unique_id = prepare_owncloud_user_id(url, username)

        # using super method as owncloud is webdav
        warnings, credentials = \
            jars.webdav.Webdav.authenticate(url,
                                            username,
                                            password,
                                            verify=verify)
        return warnings, credentials, unique_id

    def __init__(self, event_sink, storage_id, storage_cache_dir, storage_cred_reader,
                 storage_cred_writer, polling_interval=30):
        """Owncloud constructor.

        :event_sink: SyncEngine
        :storage_id: id of the storage
        :storage_cache_dir: dir for the cache
        :storage_cred_reader: read from config
        :storage_cred_writer: write in config
        :polling_interval: time between polls
        """
        # pylint: disable=too-many-arguments
        super().__init__(event_sink, storage_id, storage_cache_dir, storage_cred_reader,
                         storage_cred_writer, polling_interval)

        self.server_url = urllib.parse.urljoin(self.root_url, '../..')[:-1]
        self.shares_info = self.tree.props.get(SHARES_INFO, set())

        self.user_id_suffix = prepare_owncloud_user_id(self.server_url)

    def check_capabilities(self):
        """Check and log version

        Used in test for the time being.
        """
        url = self.server_url + '/ocs/v1.php/cloud/capabilities?format=json'
        response = self.request_session.get(url)
        response.raise_for_status()
        response_json = response.json()
        version = response_json["ocs"]["data"]["version"]
        logger.info('Remote Version: %s %s', version["edition"], version["string"])

    def check_for_changes(self, tree):
        """Poll for changes on share folders."""
        new_shares_info = self.get_shares_info()

        # create or deleted does not matter, just indicate a change via etag reset
        # this first loop triggers the event for new shared folders
        iterate_over_set_diff(new_shares_info, self.shares_info, self.tree)

        # if they exit in the tree, the etag is set to None, that will trigger
        # a change event in the recursive poller
        # this second loop triggers the update for files that are no longer shared
        iterate_over_set_diff(self.shares_info, new_shares_info, self.tree)

        # save the new_shares_info to root node so it is serialized.
        tree.props[SHARES_INFO] = new_shares_info
        self.shares_info = new_shares_info
        super().check_for_changes(tree)

    def parse_url_to_suffix(self):
        """Parse server url to obtain sp_user_id suffix."""
        url_root = urllib.parse.urlparse(self.server_url).netloc
        return ''.join('@{}'.format(url_root))

    def is_path_shared(self, path):
        """Helper function that given a path checks if it belogns to a share."""
        for share in self.shares_info:
            if tuple(path) == share.path:
                return share
        return None

    def get_tree_children(self, path, full_path=False):
        """Return the children of the node and updates the shares_info."""
        self.shares_info = self.get_shares_info()
        return super().get_tree_children(path, full_path)

    def _get_event_props_from_xml(self, elem, remote_root):
        """Update the shared fields in props."""
        path, props = \
            super()._get_event_props_from_xml(elem, remote_root)
        # setting shared prop on node
        try:
            logger.info('Setting share on: %s', path)
            share = self.is_path_shared(path)
            if share:
                props[SHARED] = True
                props['public_share'] = bool(share.share_type == '3')
                # right now public link shares are being encrypted, but only
                # with the user key and not as a share, that's decided upon
                # props['share_id'] presence
                props['share_id'] = share.share_id
            elif self.model.get_node(path).props.get(SHARED, False):
                props[SHARED] = False
                props['share_id'] = bushn.DELETE
                props['public_share'] = bushn.DELETE
            else:
                props[SHARED] = False
        except KeyError as error:
            logger.debug(error)
            props[SHARED] = False
        return path, props

    @property
    def supports_sharing_link(self):
        """:return: True if creation of public sharing links are supported."""
        return True

    @jars.webdav.error_mapper
    def create_public_sharing_link(self, path):
        """Create public sharing link of file with path.

        To create a public sharing link the base url has to be used in a POST method with the
        argument 'shareType' with a value of '3'. '3' is the value representing public sharing
        links.
        :param path: from which public sharing link should be created
        :return: URL of public sharing link.
        :throws: :class:`StorageError` if public sharing link can not be created.
        :throws: :class:`NotImplementedError` if public sharing links are not supported.
        """
        if path == []:
            raise StorageError(storage_id=self.storage_id, origin_error='Cant share root')

        url = '{}/{}'.format(self.server_url, self.SHARING_API)
        data = {'shareType': 3,  # 3 is a public link
                'path': '/' + '/'.join(path)}
        logger.info(url)
        response = self.request_session.post(url,
                                             data=data)
        response.raise_for_status()
        xml_tree = xml.etree.ElementTree.fromstring(response.text)
        inner_status_code = int(xml_tree.find('./meta/statuscode').text)
        if 400 <= inner_status_code < 600:
            raise StorageError(self.storage_id, origin_error=response.text)
        self.model.get_node(path).props['shared'] = True
        return xml_tree.find('./data/url').text

    @property
    def supports_open_in_web_link(self):
        """:return: True if creation of public web links supported."""
        return True

    @jars.webdav.error_mapper
    def create_open_in_web_link(self, path):
        """Create public web link of file with path.

        :param path: from which web link should be created
        :return: URL of public sharing link.
        :throws: :class:`StorageError` if web sharing link can not be created.
        :throws: :class:`NotImplementedError` if web links are not supported.
        """
        # check path is not None or empty
        if path is None:
            raise jars.StorageError(storage_id=self.storage_id, path=path)
        # check the folder exists
        try:
            self.model.get_node(path)
        except:
            raise jars.StorageError(storage_id=self.storage_id, path=path)
        # removing last path component as we show parent dir
        path = path[:-1]

        # escaping path
        escaped_path = urllib.parse.quote_plus('/' + '/'.join(path))

        # returning result url
        return '{}/index.php/apps/files?dir={}'.format(self.server_url,
                                                       escaped_path)

    @jars.webdav.error_mapper
    def get_shared_paths(self):
        """Return all paths which are in a sharing state."""
        def get_shared_paths(with_me=False):
            """Small helper function to the shared files."""
            params = {}
            if with_me:
                params['shared_with_me'] = 'true'
                xml_elem = 'file_target'
            else:
                xml_elem = 'path'
            response = self.request_session.get(
                '{}/{}'.format(self.server_url, self.SHARING_API),
                params=params)
            response.raise_for_status()
            xml_tree = xml.etree.ElementTree.fromstring(response.text)
            return (tuple(elm.text[1:].split('/'))
                    for elm in xml_tree.findall('.//{}'.format(xml_elem)))

        result = set(get_shared_paths(True))
        result.update(set(get_shared_paths()))
        return result

    def get_shared_folders(self):
        """Return a list of SharedFolder."""
        set_shared_folder = set()
        set_shares_info = self.get_shares_info()
        for share in set_shares_info:
            shared_folder = SharedFolder(path=share.path,
                                         share_id=share.share_id,
                                         sp_user_ids=share.sp_user_ids)
            set_shared_folder.add(shared_folder)
        return set_shared_folder

    def get_shares_info(self):
        """Return a list of ShareInfo tuples.

        To retrieve all the information from the user related shares the SHARING API is called
        using a GET method, this returns an xml with all the shares and their information.
        The paramater 'shared_with_me' can be set to True to retrieve the shares in which the
        user is not the owner, by default is set to False.
        """
        # pylint: disable=too-many-locals
        set_share_info = set()

        def process_path(path):
            """Helper function to process the path format."""
            return list(path.text[1:].split('/'))

        def get_shares_info(with_me=False):
            """Helper function that returns shared files."""
            nonlocal set_share_info
            params = {}
            # true if the user is not the owner of  the share
            if with_me:
                path_target = 'file_target'
                params['shared_with_me'] = 'true'
            else:
                path_target = 'path'
            response = self.request_session.get(
                '{}/{}'.format(self.server_url, self.SHARING_API), params=params)
            try:
                xml_tree = xml.etree.ElementTree.fromstring(response.text)
            except xml.etree.ElementTree.ParseError:
                logger.debug('No shared folders found.')
                return set()

            # get all the necessary fields
            item_source_list = xml_tree.findall('.//{}'.format('item_source'))
            folder_path_list = xml_tree.findall('.//{}'.format(path_target))
            folder_shared_with_list = xml_tree.findall(
                './/{}'.format('share_with'))
            folder_shared_by_list = xml_tree.findall('.//{}'.format('uid_owner'))
            folder_share_type_list = xml_tree.findall('.//{}'.format('share_type'))
            zip_items = zip(item_source_list, folder_path_list, folder_shared_with_list,
                            folder_shared_by_list, folder_share_type_list)
            item_dict = {}
            for item in zip_items:
                item_source, item_path, item_shared_with, folder_shared_by, share_type = item
                item_source = item_source.text

                # casefolding users
                if item_shared_with is not None and item_shared_with.text is not None:
                    item_shared_with.text = item_shared_with.text.casefold()
                if folder_shared_by is not None and folder_shared_by.text is not None:
                    folder_shared_by.text = folder_shared_by.text.casefold()

                # if the share exists in the dict
                if item_dict.get(item_source):
                    item_dict[item_source]['users'].append(item_shared_with.text +
                                                           self.user_id_suffix)
                else:
                    # if not we create it
                    item_dict[item_source] = {}
                    # In case the user is not the owner
                    # this will make that the return have only 1 user -> hacky hacky
                    if not with_me:
                        item_dict[item_source]['users'] = [folder_shared_by.text +
                                                           self.user_id_suffix]
                        if item_shared_with.text:
                            item_dict[item_source]['users'].append(item_shared_with.text +
                                                                   self.user_id_suffix)
                    else:
                        # when the user is not owner only one entry will
                        # show up for each share
                        item_dict[item_source]['users'] = [item_shared_with.text +
                                                           self.user_id_suffix]
                    # make sure all fields have the proper format
                    processed_path = process_path(item_path)
                    item_dict[item_source]['path'] = tuple(processed_path)
                    item_dict[item_source]['share_type'] = share_type.text
            for key in item_dict.keys():
                item = ShareInfo(path=item_dict[key]['path'],
                                 share_id=key + self.user_id_suffix,
                                 sp_user_ids=tuple(item_dict[key]['users']),
                                 share_type=item_dict[key].get('share_type', bushn.DELETE))
                set_share_info.add(item)
        # get items shared by the user
        get_shares_info()
        # get items share with the user
        get_shares_info(with_me=True)
        return set_share_info

    def _add_metrics(self, model, avail_bytes, used_bytes):
        """Owncloud shows strange behaviour for unlimited quota.

        See: https://github.com/owncloud/core/blob/
        d6ee1798cc5f9a641344f9e81bd3d770c6875e58/lib/public/files/fileinfo.php
        """

        # this is relevant to client#970
        if avail_bytes < 0:
            total_space = free_space = sys.maxsize
        else:
            total_space = avail_bytes + used_bytes
            free_space = avail_bytes

        model.props[METRICS] = StorageMetrics(storage_id=self.storage_id,
                                              free_space=free_space,
                                              total_space=total_space)

    def create_user_name(self):
        """Return a username with owncloud structure.

        For OC accounts the structure of the username should be 'name'@'domain'.
        """
        return prepare_owncloud_user_id(self.server_url, self.username)


def prepare_url(url, webdav_endpoint=OwnCloud.WEBDAV_ENDPOINT):
    """Prepare the passed url to reflect an owncloud webdav endpoint.

    :param url the url to be prepared for webdav access
    :param webdav_endpoint the endpoint for the webdav service
    """
    # checking if url ends with owncloud suffix
    # removing last slash
    if str.endswith(url, '/'):
        url = url[:-1]

    # parsing url
    parsed_url = urllib.parse.urlparse(url)

    # appending suffix
    if not str.endswith(parsed_url.path, webdav_endpoint):
        url += '/' + webdav_endpoint

    # appending protocol
    if len(parsed_url.scheme) == 0:
        url = "https://" + url

    return url


registered_storages.append(OwnCloud)


class NextCloud(OwnCloud):
    """NextCloud is the same as owncloud, but a different brand.

    Besides the name, the main difference is the header required to pass the CSRF check.
    """

    storage_name = 'nextcloud'
    storage_display_name = 'Nextcloud'

    def __init__(self, event_sink, storage_id, storage_cache_dir, storage_cred_reader,
                 storage_cred_writer, polling_interval=30):
        # pylint: disable=too-many-arguments
        super().__init__(event_sink, storage_id, storage_cache_dir, storage_cred_reader,
                         storage_cred_writer, polling_interval)

        # This header is required to not have requests fail with "CSRF check failed"
        self.request_session.headers['OCS-APIRequest'] = 'true'


# appending storage to available ones
registered_storages.append(NextCloud)


class Fairdocs(OwnCloud):
    """Faircheck CSP."""

    storage_name = 'fairdocs'
    storage_display_name = 'Fairdocs'

    # overriding auth type since this is bound to a url
    auth = [jars.BasicStorage.AUTH_CREDENTIALS_FIXED_URL]

    # pylint: disable=too-many-arguments
    @staticmethod
    def authenticate(url, username, password, verify=True, force=False):
        """Authenticate the user."""
        return OwnCloud.authenticate(
            'https://apps.faircheck.at/fairdocs/owncloud', username,
            password, verify=verify, force=force)


registered_storages.append(Fairdocs)


def iterate_over_set_diff(first_set, second_set, model):
    """Iterate over the differential of two given sets and Remove ETAG.

    This ensures that changes in the share state are refected as removal of ETAG, which
    triggers a refetching of the information.
    """
    for folder in first_set - second_set:
        try:
            node = model
            node.props[jars.webdav.ETAG] = None
            for path_element in folder.path:
                node = node.get_node([path_element])
                node.props[jars.webdav.ETAG] = None
        except KeyError:
            logger.exception('check for changes failed')
            first_set.discard(folder)


def prepare_owncloud_user_id(url, user_id=''):
    """Return standard user_id structure for storages with no user unique_id.

    user@domain
    """
    # This was used to trim the url to the base, with sharepoint we need the whole path.
    # Needs further testing to ensure that owncloud doesn't break due to this.
    domain = urllib.parse.urlparse(url).netloc

    # its important that this is casefold, as users from the server
    # are returned that way for shares
    user_id = '{}@{}'.format(user_id, domain).casefold()
    logger.debug('user id set to: %s', user_id)
    return user_id
