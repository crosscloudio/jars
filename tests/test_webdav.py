"""WebDAV specific storage tests."""
# pylint: disable=redefined-outer-name
import json
from unittest.mock import MagicMock, patch
import pytest
import requests
import requests_mock
import jars.webdav
# import bushn


def remove_private_props(props):
    """Removes all keys starting with a '_'."""
    return {k: v for k, v in props.items() if not k.startswith('_')}


@pytest.fixture
def webdav_storage_mock_recursive():
    """ fixture to test recursive stuff """
    dir_props = {'version_id': 'is_dir', 'is_dir': True, '_etag': 'dirid'}
    file_props = {'version_id': 'blbabl', 'is_dir': False, '_etag': 'other'}

    def get_tree_child_side_effect(*args, **kwargs):
        """ side effects helper """
        _ = kwargs
        if not args[0]:
            return [('a', dir_props)]
        elif args[0] == ['a']:
            return [('test.txt', file_props)]

    return get_tree_child_side_effect, dir_props, file_props


@pytest.mark.parametrize("error_message", [
    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:720)",
    "[Errno 1] _ssl.c:503: error:14090086:SSL routines:SSL3_GET_SERVER_CERTIFICATE:" +
    "certificate verify failed",
    "(\"bad handshake: Error([('SSL routines', 'SSL3_GET_SERVER_CERTIFICATE'," +
    " 'certificate verify failed')],)\",)"
])
def test_webdav_authenticate_certificate_validation_fail(error_message):
    """Ensure we raise exceptions when certificate verification fails."""
    with patch('requests.options', side_effect=requests.exceptions.SSLError(error_message)):
        with pytest.raises(jars.CertificateValidationError):
            assert jars.webdav.WebdavBasic.authenticate("https://host", "", "", "")


def test_webdav_authenticate_returns_credentials():
    """Ensure authenticate returns credentials dict upon success."""
    with requests_mock.mock() as mocked:
        mocked.options('https://host', text='data', headers={'DAV': 'something'})
        _, credentials = jars.webdav.WebdavBasic.authenticate("https://host",
                                                              "username",
                                                              "password")

        credentials = json.loads(credentials)
        assert credentials['server'] == "https://host"
        assert credentials['username'] == "username"
        assert credentials['password'] == "password"


# def test_poller_delete():
#     """Tests the poller, if it can detect a delete."""
#     root = bushn.Node(None)
#     root.add_child('test.txt')
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     webdav_storage_mock.get_tree_children = MagicMock(return_value=[])
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_delete.assert_called_with(
#         path=['test.txt'], storage_id='mock')

#     with pytest.raises(KeyError):
#         root.get_node(['test.txt'])


# def test_poller_delete_recursive(webdav_storage_mock_recursive):
#     """Ensure the poller is able to detect a delete in subdirectories."""
#     (get_tree_child_side_effect, dir_props, file_props) = webdav_storage_mock_recursive

#     root = bushn.Node(None)
#     node_a = root.add_child('a', dir_props.copy())
#     node_a.add_child('test.txt', file_props.copy())
#     node_a.add_child('test2.txt', file_props.copy())
#     dir_props['_etag'] = 'a child was deleted etag'
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     webdav_storage_mock.get_tree_children.side_effect = get_tree_child_side_effect
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_delete.assert_called_with(
#         path=['a', 'test2.txt'], storage_id='mock')

#     with pytest.raises(KeyError):
#         root.get_node(['a', 'test2.txt'])


# def test_poller_delete_recursive_all(webdav_storage_mock_recursive):
#     """Tests the poller if it detects a deletion of multiple subdirectories."""
#     (_, dir_props, file_props) = webdav_storage_mock_recursive
#     root = bushn.Node(None)
#     node_a = root.add_child('a', dir_props.copy())
#     node_a.add_child('test.txt', file_props.copy())
#     node_a.add_child('test2.txt', file_props.copy())
#     dir_props['_etag'] = 'a child was deleted etag'
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     webdav_storage_mock.get_tree_children = MagicMock(return_value=[])
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     # webdav_storage_mock.event_sink.storage_delete.assert_any_call(
#     #    path=['a', 'test2.txt'], storage_id='mock')
#     # webdav_storage_mock.event_sink.storage_delete.assert_any_call(
#     #    path=['a', 'test.txt'], storage_id='mock')
#     webdav_storage_mock.event_sink.storage_delete.assert_any_call(
#         path=['a'], storage_id='mock')

#     with pytest.raises(KeyError):
#         root.get_node(['a', 'test2.txt'])
#     with pytest.raises(KeyError):
#         root.get_node(['a', 'test.txt'])
#     with pytest.raises(KeyError):
#         root.get_node(['a'])


# def test_poller_create():
#     """Tests if the poller detects a create."""
#     props = {'version_id': 'hello', 'is_dir': False}
#     root = bushn.Node(None)
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     webdav_storage_mock.get_tree_children = MagicMock(
#         return_value=[('test.txt', props)])
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_create.assert_called_with(
#         path=['test.txt'], event_props=props, storage_id='mock')

#     assert root.get_node(['test.txt']).props == props


# def test_poller_create_recursive(webdav_storage_mock_recursive):
#     """Tests if the poller detects a create recursively."""
#     (get_tree_child_side_effect, dir_props, file_props) = webdav_storage_mock_recursive
#     root = bushn.Node(None)
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     webdav_storage_mock.get_tree_children.side_effect = get_tree_child_side_effect
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_create.assert_any_call(
#         path=['a', 'test.txt'], event_props=remove_private_props(file_props),
#         storage_id='mock')
#     webdav_storage_mock.event_sink.storage_create.assert_any_call(
#         path=['a'], event_props=remove_private_props(dir_props), storage_id='mock')

#     assert root.get_node(['a']).props == dir_props
#     assert root.get_node(['a', 'test.txt']).props == file_props


# def test_poller_modify():
#     """Tests if the poller detects a modify."""
#     file_props = {'is_dir': False, '_etag': 'holadrio'}
#     root = bushn.Node(None)
#     root.add_child('test.txt', file_props)
#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.model = root
#     props = file_props.copy()
#     props['_etag'] = 'Hello213'
#     webdav_storage_mock.get_tree_children = MagicMock(return_value=[('test.txt', props)])
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_modify.assert_called_with(
#         path=['test.txt'], event_props=remove_private_props(props), storage_id='mock')

#     assert root.get_node(['test.txt']).props == props


# def test_poller_modify_recursive(webdav_storage_mock_recursive):
#     """Tests if the poller detects a modify recursively."""
#     (get_tree_child_side_effect, dir_props, file_props) = webdav_storage_mock_recursive

#     root = bushn.Node(None)
#     node_a = root.add_child('a', dir_props.copy())

#     node_a.add_child('test.txt', file_props.copy())

#     file_props['_etag'] = 'Hello213'
#     dir_props['_etag'] = 'duda'

#     webdav_storage_mock = MagicMock()
#     webdav_storage_mock.model = root
#     webdav_storage_mock.storage_id = 'mock'
#     webdav_storage_mock.get_tree_children = get_tree_child_side_effect
#     event_poller = jars.webdav.RecursiveEtagEventPoller(webdav_storage_mock)
#     event_poller.check_for_changes_recursive()
#     webdav_storage_mock.event_sink.storage_modify.assert_called_with(
#         path=['a', 'test.txt'], event_props=remove_private_props(file_props),
#         storage_id='mock')

#     assert root.get_node(['a', 'test.txt']).props == file_props
#     assert root.get_node(['a']).props == dir_props


def test_serialisation(tmpdir):
    """Test serialization of webdav storage model."""
    storage = jars.webdav.Webdav(event_sink=MagicMock(),
                                 storage_id='storage_id',
                                 storage_cache_dir=str(tmpdir),
                                 storage_cred_writer=MagicMock(),
                                 storage_cred_reader=lambda:
                                 '{"password": "pw", "server": '
                                 '"u","username": "w"}',
                                 check_auth=False)

    storage.model.get_node_safe(['a']).props['name'] = 'name'

    storage.serialize()
    assert tmpdir.join('storage_model.p').exists()

    # init again
    storage = jars.webdav.Webdav(event_sink=MagicMock(),
                                 storage_id='storage_id',
                                 storage_cache_dir=str(tmpdir),
                                 storage_cred_writer=MagicMock(),
                                 storage_cred_reader=lambda:
                                 '{"password": "pw", "server": '
                                 '"u","username": "w"}',
                                 check_auth=False)

    assert storage.get_tree(cached=True).get_node(['a']).props['name'] == 'name'
