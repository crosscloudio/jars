"""
Storage implementation for WevDAV. This based on `RFC4918`_

.. _RFC4918: https://tools.ietf.org/html/rfc4918
"""
import email
import json
import logging
import urllib.parse
import xml.etree.ElementTree as ElementTree
from http import cookiejar

import requests
import requests.compat
import requests.exceptions

import bushn

import jars.utils
from jars import BasicStorage, StorageMetrics, METRICS, StorageOfflineError
from jars.request_utils import error_mapper

# pylint: disable=arguments-differ,too-many-arguments,abstract-method
logger = logging.getLogger(__name__)

ETAG = '_etag'


class BlockAll(cookiejar.CookiePolicy):
    """ a cookie plicy which blocks all cookies """
    return_ok = set_ok = domain_return_ok = \
        path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


# pylint: disable=too-many-instance-attributes
class WebdavBasic(BasicStorage):
    """ The basic WebdavStorage """

    auth = [BasicStorage.AUTH_CREDENTIALS]
    storage_name = 'webdav'
    NODE_CLASS = bushn.Node

    def clear_model(self):
        self.tree = self._create_new_tree()

    def get_internal_model(self):
        return self.tree

    def _create_new_tree(self):
        """Return a new empty tree on which update can be called."""
        logger.info('New tree requested.')
        return self.NODE_CLASS(None)

    def update(self, emit_events=False):
        """Fetches the tree and saves it into self.tree.

        This should be migrated to be the base implementation in future.
        see: https://gitlab.crosscloud.me/crosscloud/jars/issues/61
        """
        self._get_update(self.tree, emit_events)
        self._update_metrics(self.tree)

    def _get_update(self, tree, emit_events=False):
        """Return the updated tree."""
        if emit_events:
            with jars.utils.emit_events(tree, self.event_sink, self.storage_id):
                self.check_for_changes(tree)
        else:
            self.check_for_changes(tree)

        return tree

    def check_for_changes(self, tree):
        """If the root has changed, call check_for_changes_recursive as required."""

        # First get current root props on remote
        root_props = self.get_root_props()

        # Compare root eTag to eTag currently held in the tree.
        etag = root_props[ETAG]
        if etag != tree.props.get(ETAG):
            logger.info('Root etag changed: %s != %s', tree.props.get(ETAG), etag)

            self.check_for_changes_recursive(tree=tree)

            # Set the new etag.
            with tree.lock:
                logger.info('Setting new root etag %s', etag)
                tree.props[ETAG] = etag

    def check_for_changes_recursive(self, tree, path=None):
        """Compare the cached tree with the ETags on the branches where they are changed"""
        if path is None:
            path = []

        children = self.get_tree_children(path)
        logger.debug("< /%s > contains %s:",
                     '/'.join(path), [child[0] for child in children])

        # check for adds and modifies
        for child_name, props in children:
            change_detected = False
            child_path = path + [child_name]
            try:
                node = tree.get_node(path=child_path)
                if node.props.get(ETAG) != props[ETAG]:
                    # if etag of node has changed:
                    # write the new etag in the model
                    change_detected = True
                    node.props = props
            except KeyError:
                parent = tree.get_node(path)
                change_detected = True
                node = parent.add_child(name=child_name, props=props)

            if change_detected and props[jars.IS_DIR]:
                self.check_for_changes_recursive(tree=tree, path=child_path)

        original_children = []
        try:
            original_children = tree.get_node(path).children
        except KeyError:
            pass

        # detect deletions
        for child in list(original_children):
            for child_name, props in children:
                if child_name == child.name:
                    break
            else:
                logger.debug("delete: %s", child.path)
                # remove from model
                tree.get_node(child.path).delete()

    def get_tree(self, cached=False, **kwargs):
        """

        This will soon be the new base implementation. Then it can be removed here.
        see: https://gitlab.crosscloud.me/crosscloud/jars/issues/61
        """
        logger.debug('get tree kwargs %s', kwargs)

        if cached:
            tree = self.tree
        else:
            tree = self._get_update(self._create_new_tree())

        self._update_metrics(tree)

        with tree.lock:
            filtered_tree = jars.utils.filter_tree_by_path(tree, self.filter_tree)

        return filtered_tree

    # pylint: disable=unused-argument
    @staticmethod
    def authenticate(url, username, password, verify=True, force=False):
        try:
            response = requests.options(
                url, auth=(username, password), verify=verify,
                headers={'User-Agent': 'CrossCloud/{}'.format(jars.__version__)})
            response.raise_for_status()
            assert 'DAV' in response.headers, "URL does not point to WebDAV server"
        except requests.exceptions.SSLError as ssl_error:
            # There appears to be no other way other than creating a ssl_context by hand
            # and do a manual handshake. This is a simple and stupid version but it
            # should work.
            # Something is wrapping the exception handling for ssl sockets along the way.
            # That is the reason for the two different 'certificate verify failed' checks.
            if 'CERTIFICATE_VERIFY_FAILED' in str(ssl_error) or \
                    'certificate verify failed' in str(ssl_error):
                logger.info("Server certificate for '%s' not trusted. Aborting.", url)
                raise jars.CertificateValidationError(storage_id=WebdavBasic.storage_name,
                                                      origin_error=ssl_error,
                                                      path='/')

            # Something else happened, we also want to abort.
            return ['Unable to establish a secure connection with the server!'], None

        # writing auth data to keychain
        auth_data = {'server': url, 'username': username, 'password': password}
        credentials = json.dumps(auth_data)
        return [], credentials

    def check_available(self):
        # check authentication
        try:
            self._get_metrics()
        except BaseException as ecx:
            raise StorageOfflineError(storage_id=self.storage_id, origin_error=ecx)

    def __init__(self, event_sink, storage_id, storage_cache_dir,
                 storage_cred_reader, storage_cred_writer, polling_interval=30,
                 check_auth=True):
        # pylint: disable=unused-argument
        super().__init__(event_sink, storage_id, storage_cache_dir=storage_cache_dir)

        # loading authdata -> stored in locacal credential storage as JSON
        auth_data = json.loads(storage_cred_reader())
        self.root_url = auth_data['server']
        self.username = auth_data['username']
        password = auth_data['password']

        self._storage_id = storage_id

        self.polling_interval = polling_interval

        # fixing the root url of the webdav endpoint
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.remote_root = requests.compat.urlsplit(self.root_url).path

        # this is used as connection pool
        self.request_session = requests.Session()

        # set the User-Agent to crosscloud + version
        self.request_session.headers['User-Agent'] = 'CrossCloud/{}'.format(
            jars.__version__)

        # block all cookies
        self.request_session.cookies.set_policy(BlockAll())

        # setting up session using auth data
        self.request_session.auth = (self.username, password)

        # initialising poller getting updates from the server
        self.poller = None

    def init_poller(self):
        """Return the poller."""
        def set_offline(value):
            """Set the offline state."""
            self.offline = value
        return jars.PollingScheduler(interval=self.polling_interval,
                                     target=self.update,
                                     target_kwargs={'emit_events': True},
                                     offline_callback=set_offline)

    def start_events(self):
        """ starts the event poller """
        if (self.poller and not self.poller.is_alive()) or not self.poller:
            # recreate poller instance
            self.poller = self.init_poller()
            self.poller.start()

    def stop_events(self, join=False):
        """ stops the event poller """
        self.poller.stop(join=join)

    @error_mapper
    def _write(self, path, file_obj, original_version_id=None, size=0):
        """ The original version id is checked with a If header """

        # todo: use size
        _ = size

        def chunker(file_obj, chunksize=1024 * 16):
            """generator to upload the file"""
            while True:
                buf = file_obj.read(chunksize)
                if not buf:
                    break
                yield buf

        self.make_dir(path[:-1])
        oc_path = self._cc_to_oc_url(path)
        headers = {}
        if original_version_id is not None:
            headers['If'] = '([{}])'.format(original_version_id)

        response = self.request_session.put(oc_path, headers=headers,
                                            data=chunker(file_obj))
        response.raise_for_status()
        return response.headers['ETag']

    def create_public_sharing_link(self, path):
        raise NotImplementedError()

    def create_open_in_web_link(self, path):
        raise NotImplementedError()

    @error_mapper
    def delete(self, path, original_version_id):
        """ The original version id is checked with a If header """
        oc_url = self._cc_to_oc_url(path)

        headers = {}

        if original_version_id is not None and original_version_id != jars.IS_DIR:
            headers['If'] = '([{}])'.format(original_version_id)

        response = self.request_session.request('DELETE', oc_url,
                                                headers=headers)
        response.raise_for_status()

    @error_mapper
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """ The original version id is checked with a If header """

        self.make_dir(target[:-1])
        oc_source_path = self._cc_to_oc_url(source)
        oc_target_path = self._cc_to_oc_url(target)
        oc_source_rel_path = self._cc_to_oc_rel_url(source)
        oc_target_rel_path = self._cc_to_oc_rel_url(target)

        headers = {'Destination': oc_target_path,
                   'Depth': 'infinity'}

        if_headers = []
        # if header defined in Saber dav at
        # https://github.com/fruux/sabre-dav/blob/master/lib/DAV/Server.php
        # line 1484
        if expected_source_vid is not None and expected_source_vid != jars.IS_DIR:
            if_headers.append('<{}> ([{}])'.format(oc_source_rel_path,
                                                   expected_source_vid))
        if expected_target_vid is not None and expected_target_vid != jars.IS_DIR:
            if_headers.append('<{}> ([{}])'.format(oc_target_rel_path,
                                                   expected_target_vid))

        if if_headers:
            headers['If'] = ' '.join(if_headers)

        response = self.request_session.request('MOVE', oc_source_path,
                                                headers=headers)
        response.raise_for_status()

        # return version id of target
        response = self.request_session.request('HEAD', oc_target_path)
        response.raise_for_status()
        return response.headers.get('ETag', jars.IS_DIR)  # directories have no etag

    @error_mapper
    def make_dir(self, path):
        """ creates a directory recursivly, do not throw """
        sub_path = []
        for elm in path:
            sub_path.append(elm)
            oc_url = self._cc_to_oc_url(sub_path)
            response = self.request_session.request('MKCOL', oc_url)
            # already exists, (409 is rfc, 405 oc)
            if response.status_code in (409, 405):
                continue
            response.raise_for_status()
        return jars.IS_DIR

    def _cc_to_oc_url(self, path):
        return self.root_url + urllib.parse.quote('/'.join(path))

    def _cc_to_oc_rel_url(self, path):
        return urllib.parse.urlparse(self.root_url).path \
            + urllib.parse.quote('/'.join(path))

    @error_mapper
    def open_read(self, path, expected_version_id=None):
        """ expeted version_id is check via the http If header """
        oc_path = self._cc_to_oc_url(path)
        # 'Accept-Encoding' is removed from the header until
        # https://github.com/shazow/urllib3/issues/437
        # is fixed and merged into requests
        headers = {'Accept-Encoding': None}
        if expected_version_id is not None:
            headers['If'] = '([{}])'.format(expected_version_id)
        response = self.request_session.get(oc_path, stream=True, headers=headers)
        response.raise_for_status()
        response.raw.decode_content = True
        return response.raw

    @error_mapper
    def get_root_props(self):
        """Return the properties of the root node."""
        res = self.request_session.request('PROPFIND', self.root_url,
                                           headers={'Depth': '0'})
        res.raise_for_status()
        xml_tree = ElementTree.fromstring(res.text)
        elem = xml_tree.find('{DAV:}response')
        props = self._get_event_props_from_xml(elem, remote_root=self.remote_root)[1]
        return props

    @error_mapper
    def get_tree_children(self, path, full_path=False):
        oc_path = self._cc_to_oc_url(path) + '/'
        result = []
        res = self.request_session.request('PROPFIND', oc_path,
                                           headers={'Depth': '1'})
        res.raise_for_status()
        # logger.debug(res.text)
        xml_tree = ElementTree.fromstring(res.text)
        for elem in xml_tree.findall('{DAV:}response'):

            try:
                elem_path, props = self._get_event_props_from_xml(
                    elem, remote_root=self.remote_root)
            except TypeError:
                logger.info("ignoring files because missing field or parsing error")
                continue
            # ignore the tempdir, and all childs
            if elem_path[:1] == [jars.BasicStorage.TEMPDIR]:
                continue

            # ignore the root
            if elem_path == path:
                continue
            if full_path:
                result.append((elem_path, props))
            else:
                elem_name = None
                if len(elem_path):
                    elem_name = elem_path[-1]
                result.append((elem_name, props))
        return result

    supports_serialization = True

    def _get_event_props_from_xml(self, elem, remote_root):
        """ gets the cc-style properties from a webdav service """
        # one should be able to overload this
        # pylint: disable=no-self-use
        is_dir = len(list(elem.find('.//{DAV:}resourcetype'))) > 0
        name = requests.compat.unquote(_prop(elem, 'href'))
        name = name.replace(remote_root, '')
        event_props = {jars.IS_DIR: is_dir}
        if is_dir:
            event_props['version_id'] = jars.IS_DIR
            event_props['size'] = 0
        else:
            event_props['version_id'] = _prop(elem, 'getetag')

            event_props['size'] = int(_prop(elem, 'getcontentlength'))

        date = email.utils.parsedate_to_datetime(_prop(elem, 'getlastmodified'))
        event_props['modified_date'] = date
        event_props['_etag'] = _prop(elem, 'getetag')

        # remove leading and trailing slashes
        if name.startswith('/'):
            name = name[1:]
        if name.endswith('/'):
            name = name[:-1]

        # when root there is no name
        if name:
            path = name.split('/')
        else:
            path = []

        return path, event_props

    def _update_metrics(self, model):
        """
        Updates metrics and stores it in root of model.
        """
        avail_bytes, used_bytes = self._get_metrics()
        self._add_metrics(model, avail_bytes, used_bytes)

    @error_mapper
    def _get_metrics(self):
        """ fetches and returns metrics """

        # create requesting xml
        ElementTree.register_namespace('D', 'DAV:')
        root_element = ElementTree.Element('{DAV:}propfind')
        prop_element = ElementTree.SubElement(root_element, '{DAV:}prop')
        ElementTree.SubElement(prop_element, '{DAV:}quota-available-bytes')
        ElementTree.SubElement(prop_element, '{DAV:}quota-used-bytes')
        xml = ElementTree.tostring(root_element, method='xml')

        res = self.request_session.request(method='PROPFIND', url=self.root_url,
                                           headers={'Depth': '0'}, data=xml)
        res.raise_for_status()

        response_xml = ElementTree.fromstring(text=res.text)
        avail_bytes = int(response_xml.find('.//{DAV:}quota-available-bytes').text)
        used_bytes = int(response_xml.find('.//{DAV:}quota-used-bytes').text)

        return (avail_bytes, used_bytes)

    def _add_metrics(self, model, avail_bytes, used_bytes):
        """
        This method should be overwritten in order customize certain behaviour.
        """
        model.props[METRICS] = StorageMetrics(storage_id=self.storage_id,
                                              free_space=avail_bytes,
                                              total_space=avail_bytes + used_bytes)


class Webdav(jars.utils.WriteToTempDirMixin, WebdavBasic):
    """ Webdav with  WriteToTempDirMixin mixin   """
    pass


def _prop(elem, name, default=None):
    """ helper function to get a property from a webdav resource xml """
    child = elem.find('.//{DAV:}' + name)
    return default if child is None else child.text


# def main():
#     import io
#
#     def storage_delete(self, storage_id, path):
#         print('DEL', path)
#
#     def storage_modify(self, storage_id, path, event_props):
#         print('MOD', path, event_props)
#
#
# def poller_main():
#     asd = Webdav('http://localhost/remote.php/webdav', ('davy', 'davy'),
#                  EventSyncTester(), 'asd', polling_interval=0.2)
#     asd.update()
#     asd.start_events()
#     sleep(120)


# def main():
#     import io
#
#     # logging.basicConfig(level=logging.DEBUG)
#
#     # wd = Webdav('http://localhost/remote.php/webdav',
#     #            ('davy', 'davy'), None, None, None)
#
#     # tree = wd.get_tree()
#
#     # print(tree.props)
#     # for node in tree:
#     #    print(node.path)
#     # version_id = tree.get_node(['test.txt']).props['version_id']
#     # print(tree.get_node(['Photos', 'Paris.jpg']).props)
#
#     # data = ''''''
#     # generate a sharing link:
#     # response = requests.request('GET',
#     #                             'http://localhost/',
#     #                             auth=('davy', 'davy'))
#     #
#     # print(response.headers)
#     #
#     # print(response.encoding)
#     #
#     # print(len(response.text))
#     # print(response.text)
#     # xml_tree = xml.etree.ElementTree.fromstring(response.text)
#     # print([elm.text for elm in xml_tree.findall('.//file_target')])
#     # # print(response.text)
#     #
#     #
#
#     # f_out = wd.open_read(['testa.txt'], expected_version_id='asd')
#     # f_out = wd.write(['tests.txt'], io.BytesIO(b''), original_version_id=None)
#
#     # tree.get_node_safe('a',a/c/])
#
#
# if __name__ == "__main__":
#     main()
