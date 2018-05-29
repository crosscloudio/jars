"""Tests for Dropbox only functionality."""
import os
import tempfile
from unittest import mock
from unittest.mock import MagicMock
from io import BytesIO
import logging
import requests
import requests_mock
import pytest

import bushn
import jars.dropbox
from jars import InvalidOperationError, AccessDeniedError, casefold_path
from jars.dropbox import dropbox_client_error_mapper, _is_shared, \
    as_crosscloud_path, as_dropbox_path, DropboxTreeToSyncEngineAdapter
from jars.utils import get_node_safe
from jars.utils import normalize_path

from tests.setup import SetupStorage


class DropboxSetup(SetupStorage):
    """Properties required to initialize a Dropbox test."""
    STORAGE_CLASS = jars.dropbox.Dropbox
    NODE_CLASS = bushn.IndexingNode
    NAME = 'dropbox'
    ROOT_INIT_PARAMS = {'name': None,
                        'indexes': ['_id']
                        }


def init_dropbox(storage_cache_dir=tempfile.gettempdir()):
    """Initialize Test Dropbox storage."""
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("requests_oauthlib.oauth2_session").setLevel(logging.WARNING)
    return jars.dropbox.Dropbox(storage_id='dropbox',
                                event_sink=MagicMock(),
                                storage_cache_dir=storage_cache_dir,
                                storage_cred_reader=lambda: '{"access_token":123}',
                                storage_cred_writer=None)


@pytest.fixture()
def init_dropbox_with_shared_folder():
    """Initialize Test Dropbox storage."""
    with mock.patch("jars.dropbox.Dropbox", new=MagicMock()):
        storage = jars.dropbox.Dropbox(storage_id='dropbox',
                                       event_sink=MagicMock(),
                                       storage_cache_dir=tempfile.gettempdir(),
                                       storage_cred_reader=lambda: '{"access_token":123}',
                                       storage_cred_writer=None)

        storage.model = bushn.IndexingNode('root', indexes=['_id', '_shared_folder_id'])
        folder_a = storage.model.add_child('a', {'_id': '1'})
        folder_a.add_child('b', {'_id': '2', '_shared_folder_id': '12345'})

        # Ensure the our shared node is actually part of the index.
        assert storage.model.index['_shared_folder_id'].keys() == {'12345'}

        # Ensure the share_id is properly set from the fixture.
        shared_node = storage.model.index['_shared_folder_id']['12345']
        assert shared_node.props['_shared_folder_id'] == '12345'

        assert len(storage.model) == 2 + 1
        return storage


@pytest.mark.parametrize('status_code, text, expected_raised_exeption', [
    (409, '{"error_summary": "path/not_found/..."}', FileNotFoundError),
    (409, '{"error_summary": "path/malformed_path/.."}', InvalidOperationError),
    (409, '{"error_summary": "path/disallowed_name/..."}', InvalidOperationError),
    (409, '{"error_summary": "path/conflict/."}', InvalidOperationError),
    (409, '{"error_summary": "path/no_write_permission/."}', AccessDeniedError),
    # (409, '{"error_summary": "insufficient_space"}', NoSpaceError),
])
def test_dropbox_handling_client_errors(status_code, text, expected_raised_exeption):
    """Ensure that all thrown exceptions are mapped properly."""
    with pytest.raises(expected_raised_exeption):
        decorated_dummy_request(status_code, text)


def test__is_shared():
    """Ensure that is_shared properly returns whether an item is shared."""
    assert not _is_shared({})
    assert _is_shared({'share_id': 1})
    assert _is_shared({'public_share': 'url'})
    assert _is_shared({'share_id': 1, 'public_share': 'url'})
    assert not _is_shared({'share_id': bushn.DELETE, 'public_share': bushn.DELETE})
    assert _is_shared({'share_id': bushn.DELETE, 'public_share': 'url'})
    assert _is_shared({'share_id': 1, 'public_share': bushn.DELETE})


@pytest.mark.skip
def test_add_remove_shared_folders():
    """Ensure correct handling of folders shared between dropbox users."""
    dbx = init_dropbox()

    payload_list_folder = {'entries': [{'.tag': 'folder', 'id': 'folder1', 'path_lower': '/1'},
                                       {'.tag': 'file', 'id': 'file1', 'path_lower': '/1/1.txt',
                                        'content_hash': 'deadbeef'}],
                           'cursor': 'initial',
                           'has_more': False}

    # TODO XXX: Add paginated tests
    payload_list_shared_links = {'links': []}

    payload_list_shared_folders = {'links': []}

    def payload_list_folder_continue():
        """Payload for list_folder/continue."""
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'sharing_info': {'shared_folder_id': '123'},
                            'path_display': '/Shared',
                            'path_lower': '/shared'}],
               'cursor': 'page2',
               'has_more': False}
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'path_display': '/Shared',
                            'path_lower': '/shared'}],
               'cursor': 'page3',
               'has_more': False}
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'sharing_info': {'shared_folder_id': '123'},
                            'path_display': '/Shared',
                            'path_lower': '/shared'}],
               'cursor': 'page4',
               'has_more': False}
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'path_display': '/Shared',
                            'path_lower': '/shared'}],
               'cursor': 'page5',
               'has_more': False}
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'path_display': '/Shared',
                            'path_lower': '/shared'}],
               'cursor': 'page6',
               'has_more': False}

    payload_get_usage = {'used': 0, 'allocation': {'allocated': 1000}}

    with requests_mock.Mocker() as rmock:
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/users/get_space_usage',
                           json=payload_get_usage)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder',
                           json=payload_list_folder)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder/continue',
                           2 * [{'json': f} for f in payload_list_folder_continue()])
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/sharing/list_shared_links',
                           json=payload_list_shared_links)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/sharing/list_folders',
                           json=payload_list_shared_folders)

        # Initially setup the tree
        assert jars.CURSOR not in dbx.get_internal_model().props
        dbx.update()
        model = dbx.get_internal_model()
        assert model.props[jars.CURSOR] == 'initial'
        assert len(model) == 2 + 1
        assert len(dbx.get_internal_model().props['_share_id_list']) == 1

        # Add 'shared' folder and ensure properties are set and the id shows up in the index.
        # Ensure we are at the second page and the internal model reflects that in the cursor.
        dbx.update()
        model = dbx.get_internal_model()
        assert model.props[jars.CURSOR] == 'page2'

        assert '123' in dbx.get_internal_model().props['_share_id_list']
        node = dbx.get_internal_model().props['_share_id_list'].get('123')
        assert 'folder4' in node.props['_id']
        assert node.props.get('shared', None)
        assert len(model) == 3 + 1
        assert len(dbx.get_internal_model().props['_share_id_list']) == 1

        dbx.update()
        model = dbx.get_internal_model()
        assert model.props[jars.CURSOR] == 'page3'

        assert '123' not in dbx.get_internal_model().props['_share_id_list']
        assert len(dbx.get_internal_model().props['_share_id_list']) == 0
        assert len(model) == 3 + 1

        node = model.index['_id'].get('folder4')
        assert node.props['shared'] is False


@pytest.mark.skip
def test_add_remove_shared_links():
    """Ensure correct handling of publicly shared links via dropbox."""
    dbx = init_dropbox()

    payload_list_folder = {'entries': [
        {'.tag': 'folder', 'id': 'folder1', 'path_lower': '/1'},
        {'.tag': 'folder', 'id': 'folder2', 'path_lower': '/2'},
        {'.tag': 'file', 'id': 'file1', 'path_lower': '/1/1.txt', 'content_hash': 'deadbeef'}],
        'cursor': 'initial',
        'has_more': False}

    def payload_list_shared_links():
        """Payload for sharing/list_shared_links."""
        yield {'links': []}
        yield {'links': [{'url': 'http://dbx.local/folder1', 'id': 'folder1', 'path_lower': '/1'},
                         {'url': 'http://dbx.local/folder2', 'id': 'folder2', 'path_lower': '/2'}]}
        yield {'links': [{'url': 'http://dbx.local/folder2', 'id': 'folder2', 'path_lower': '/2'}]}
        yield {'links': []}

    payload_get_usage = {'used': 0, 'allocation': {'allocated': 1000}}

    with requests_mock.Mocker() as rmock:
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/users/get_space_usage',
                           json=payload_get_usage)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder',
                           json=payload_list_folder)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder/continue',
                           json={'entries': [], 'cursor': 'foo'})
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/sharing/list_shared_links',
                           2 * [{'json': f} for f in payload_list_shared_links()])

        # Initially setup the tree
        assert jars.CURSOR not in dbx.get_internal_model().props
        dbx.update()
        # pylint: disable=protected-access
        dbx._update_shared_links(model=dbx.get_internal_model())
        model = dbx.get_internal_model()
        assert model.props[jars.CURSOR] == 'initial'
        assert len(model) == 3 + 1
        assert len(model.index['_id']) == 3
        assert len(model.index['_shared_link']) == 0

        # Share links for folder 1 and 2
        dbx.update()
        # pylint: disable=protected-access
        dbx._update_shared_links(model=dbx.get_internal_model())
        model = dbx.get_internal_model()
        assert len(model.index['_id']) == 3

        for folder_id in ['folder1', 'folder2']:
            assert model.index['_id'].get(folder_id).props.get('shared', False)


@pytest.mark.skip
def test_pagination():
    """Ensure paginated changes are handled properly by `update` and `get_tree`."""
    dbx = init_dropbox()

    payload_list_folder = {'entries': [
        {'.tag': 'folder', 'id': 'folder1', 'path_lower': '/1'},
        {'.tag': 'file', 'id': 'file1', 'path_lower': '/1/2/3.txt', 'content_hash': 'deadbeef'},
        {'.tag': 'folder', 'id': 'folder2', 'path_lower': '/1/2'}],
        'cursor': 'this_is_page_one',
        'has_more': True}

    def payload_list_folder_continue():
        """Return data for endpoints."""
        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder4',
                            'path_display': '/4',
                            'path_lower': '/4'},
                           {'.tag': 'file',
                            'id': 'file2',
                            'path_display': '/1/2/5.txt',
                            'path_lower': '/1/2/5.txt',
                            'content_hash': 'deadbeaf'}],
               'cursor': 'page2',
               'has_more': True}

        yield {'entries': [{'.tag': 'file',
                            'id': 'file7',
                            'path_display': '/1/2/7.txt',
                            'path_lower': '/1/2/7.txt',
                            'content_hash': 'deedbea7f'}],
               'cursor': 'page3',
               'has_more': True}

        yield {'entries': [{'.tag': 'folder',
                            'id': 'folder10',
                            'path_lower': '/10'},
                           {'.tag': 'file',
                            'id': 'file3',
                            'path_display': '/1/2/6.txt',
                            'path_lower': '/1/2/6.txt',
                            'content_hash': 'deedbeaf'}],
               'cursor': 'last_page',
               'has_more': False}

    payload_get_usage = {'used': 0, 'allocation': {'allocated': 1000}}

    with requests_mock.Mocker() as rmock:
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/users/get_space_usage',
                           json=payload_get_usage)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder',
                           json=payload_list_folder)
        rmock.register_uri('POST', 'https://api.dropboxapi.com/2/files/list_folder/continue',
                           2 * [{'json': f} for f in payload_list_folder_continue()])

        assert jars.CURSOR not in dbx.get_internal_model().props
        dbx.update()
        assert dbx.get_internal_model().props[jars.CURSOR] == 'last_page'
        assert len(dbx.get_internal_model()) == 8 + 1

        dbx.clear_model()
        tree_internal = dbx.get_tree(with_display_path=False)
        tree_cached = dbx.get_tree(cached=True, with_display_path=False)
        assert len(tree_internal) == 8 + 1
        assert len(tree_cached) == 0 + 1


@pytest.mark.skip
@pytest.mark.usefixtures("init_dropbox_with_shared_folder")
def test_get_shared_folders():
    """Ensure that get_shared_folders returns 'users' from a given share."""
    payload_list_folder_members = {'groups': [],
                                   'invitees': [],
                                   'users': [{'access_type': {'.tag': 'owner'},
                                              'user': {'account_id': 'dbid:accountowner0'}}],
                                   'cursor': 'token'}

    def payload_list_folder_members_continue():
        """Payload with pagination."""
        yield {'groups': [],
               'invitees': [],
               'users': [{'access_type': {'.tag': 'editor'},
                          'user': {'account_id': 'dbid:editor0'}},
                         {'access_type': {'.tag': 'editor'},
                          'user': {'account_id': 'dbid:editor1'}}
                         ],
               'cursor': 'token'}
        # Last page. No cursor present.
        yield {'groups': [],
               'invitees': [],
               'users': [{'access_type': {'.tag': 'editor'},
                          'user': {'account_id': 'dbid:owner2'}},
                         {'access_type': {'.tag': 'editor'},
                          'user': {'account_id': 'dbid:owner3'}}
                         ]}

    with requests_mock.Mocker() as rmock:
        rmock.register_uri('POST',
                           'https://api.dropboxapi.com/2/sharing/list_folder_members',
                           json=payload_list_folder_members)
        rmock.register_uri('POST',
                           'https://api.dropboxapi.com/2/sharing/list_folder_members/continue',
                           [{'json': f} for f in payload_list_folder_members_continue()])
        rmock.register_uri('POST',
                           'https://api.dropboxapi.com/2/users/get_current_account',
                           json={'account_id': 'dbid:accountowner0'})

        dbx = init_dropbox_with_shared_folder()

        # Fetch shared folders.
        shared_folders = dbx.get_shared_folders()
        assert len(shared_folders) == 1

        # Ensure the SharedFolder object is populated properly.
        sfo = shared_folders[0]
        assert isinstance(sfo, jars.SharedFolder)
        assert sfo.path == ['root', 'a', 'b']
        assert sfo.share_id == '12345'

        # Account Owner (current unique id) has to be part of the list
        assert 'dbid:accountowner0' in sfo.sp_user_ids
        # Ensure everyone else is in the list.
        assert 'dbid:owner3' in sfo.sp_user_ids
        assert 'dbid:owner2' in sfo.sp_user_ids
        assert 'dbid:editor1' in sfo.sp_user_ids
        assert 'dbid:editor0' in sfo.sp_user_ids

        dbx.clear_model()
        assert dbx.get_shared_folders() == []


def test_path_transformations():
    """Ensure the proper transformation of crosscloud and dropbox paths."""
    assert as_crosscloud_path("/") == ['']

    # files/list_folder and shares/list_folder endpoints expect an empty string to indicate root
    # folder.
    assert as_dropbox_path(['/']) == ""
    assert as_dropbox_path([]) == ""
    assert as_dropbox_path(['']) == ""

    assert as_dropbox_path(['foobar']) == "/foobar"
    assert as_dropbox_path(['foo', 'bar', 'baz']) == "/foo/bar/baz"
    assert as_crosscloud_path("/a/bb/ccc/test.txt") == ['a', 'bb', 'ccc', 'test.txt']
    assert as_dropbox_path(['a', 'bb', 'ccc', 'test.txt']) == "/a/bb/ccc/test.txt"

    test_filename = "ÄÄÄÖÖÖXXX.txt"
    assert as_crosscloud_path(test_filename) == [test_filename]
    assert as_crosscloud_path("/" + test_filename) == [test_filename]
    assert as_crosscloud_path("/" + test_filename, normalize=False) == [test_filename]

    def as_crosscloud_path_normalized(path, expected_path):
        """Match normalized path."""
        assert as_crosscloud_path(path, normalize=True) == expected_path

    as_crosscloud_path_normalized("/AA/BbÖ/" + test_filename,
                                  normalize_path(["aa", "bbö", test_filename]))

    def as_crosscloud_path_not_normalized(path, expected_path):
        """Match non-normalized path."""
        assert as_crosscloud_path(path, normalize=False) == expected_path

    as_crosscloud_path_not_normalized("/AA/BbÖ/" + test_filename, ["AA", "BbÖ", test_filename])
    as_crosscloud_path_not_normalized("/aa/bbÖ/" + test_filename, ["aa", "bbÖ", test_filename])
    as_crosscloud_path_not_normalized("aa/bbÖ/" + test_filename, ["aa", "bbÖ", test_filename])


@pytest.mark.skip
def test_serialisation():
    """Test serialisation of dropbox storage model."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = init_dropbox(tmp_dir)

        # pylint: disable=unused-argument
        def add_file_metadata_to_model(model, path, metadata):
            """Dummy for adding file to model."""
            lower_path = casefold_path(path)
            with model.lock:
                node_props = get_node_safe(model, lower_path).props
                node_props['name'] = 'name'

        with mock.patch('jars.dropbox.add_file_metadata_to_model',
                        new=add_file_metadata_to_model):
            # upload dummy file
            storage.write(path=['a'], file_obj=BytesIO(bytes('empty', 'UTF-8')))
            storage.get_tree(cached=True).get_node(['a'])

        storage.serialize()
        os.path.exists(os.path.join(tmp_dir, 'storage_model.p'))

        # init again
        storage = init_dropbox(tmp_dir)
        assert storage.get_tree(cached=True).get_node(['a']).props['name'] == 'name'


@dropbox_client_error_mapper
def decorated_dummy_request(status_code, text):
    """Dummy request helper used to test mapped exceptions."""
    with requests_mock.Mocker() as mocker:
        mocker.get('http://www.dropbox.com', status_code=status_code, text=text)
        response = requests.get('http://www.dropbox.com')
        response.raise_for_status()


def test_dropbox_tree_to_sync_engine_adapter_transform_path():
    """Ensure that the custom dropbox adapter properly transforms given paths."""
    root = bushn.Node("root", parent=None, props={'cursor': None})
    adapter = DropboxTreeToSyncEngineAdapter(node=root, sync_engine=None, storage_id='test')

    assert root.parent is None
    assert adapter.transform_path(root) == []

    node_a = bushn.Node("a", parent=root, props={'_path_display_node': 'a', '_id': 'id:1'})
    assert '_path_display_node' in node_a.props

    assert adapter.transform_path(node_a) == ['a']

    node_b = bushn.Node("b", parent=node_a, props={'_path_display_node': 'b', '_id': 'id:2'})
    assert '_path_display_node' in node_b.props
    assert adapter.transform_path(node_b) == ['a', 'b']

    node_c = bushn.Node("c", parent=node_b, props={'_path_display_node': 'c', '_id': 'id:3'})
    assert adapter.transform_path(node_c) == ['a', 'b', 'c']


def test_default_node():
    """If model_load fails we still need certain props to be true on the model."""
    node = init_dropbox().model
    assert isinstance(node, bushn.IndexingNode)
    assert node.props['_id'] == jars.dropbox.ROOT_NODE_ID
    assert jars.dropbox.SHARE_ID_INDEX_NAME in node.props
    assert jars.dropbox.PUBLIC_SHARE_INDEX_NAME in node.props
