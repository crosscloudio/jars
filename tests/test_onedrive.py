"""Tests for OneDrive only functionality
"""
# pylint: disable=redefined-outer-name
import datetime as dt
import json
import logging
from unittest.mock import Mock

import mock
import pytest
import pytz
import termcolor
from requests import HTTPError

import bushn
from jars import IS_DIR, VERSION_ID
from jars.microsoft import onedrive
from jars.microsoft import onedrive_for_business
from tests.setup import SetupStorage
from tests.test_storage import init_onedrive

TEST_ID = 'IsBiglyAWord'

logger = logging.getLogger(__name__)


class OneDriveSetup(SetupStorage):
    """Properties required to initialize a OneDrive test."""
    STORAGE_CLASS = onedrive.OneDrive
    NODE_CLASS = bushn.IndexingNode
    ROOT_INIT_PARAMS = {'name': None,
                        'indexes': ['_id']
                        }
    NAME = 'onedrive'

    @property
    def init_params(self):
        """Parameters used to initialize the Onedrive

        The additional parameter polling_interval is needed.
        """
        params = super().init_params
        params['polling_interval'] = 1
        return params


class OneDriveForBussinessSetup(OneDriveSetup):
    """Properties required to initialize a OneDrive for Business test."""
    STORAGE_CLASS = onedrive_for_business.OneDriveBusiness
    NAME = 'onedrive_business'

ITEM_META = {'cTag': 'adDo1RDIzRUQzOTFCN0JFNUFEITEwMS42MzYyODgxMjQzMDI0NzAwMDA',
             'createdBy': {'application': {'id': '40191814'},
                           'user': {'displayName': 'Finn Huckleberry',
                                    'id': '5d23ed391b7be5ad'}},
             'createdDateTime': '2017-03-13T14:10:24.543Z',
             'eTag': 'aNUQyM0VEMzkxQjdCRTVBRCExMDEuMQ',
             'fileSystemInfo': {'createdDateTime': '2017-03-13T14:10:24.543Z',
                                'lastModifiedDateTime': '2017-04-03T12:09:44.456Z'},
             'folder': {'childCount': 0,
                        'folderView': {'sortBy': 'takenOrCreatedDateTime',
                                       'sortOrder': 'ascending',
                                       'viewType': 'thumbnails'}},
             'id': '5D23ED391B7BE5AD!101',
             'lastModifiedBy': {'application': {'id': '44048800'},
                                'user': {'displayName': 'Finn Huckleberry',
                                         'id': '5d23ed391b7be5ad'}},
             'lastModifiedDateTime': '2017-04-26T14:07:10.247Z',
             'name': 'root',
             'parentReference': {'driveId': '5d23ed391b7be5ad',
                                 'id': '5D23ED391B7BE5AD!0',
                                 'path': '/drive/root:'},
             'root': {},
             'size': 0,
             'webUrl': 'https://onedrive.live.com/?cid=5d23ed391b7be5ad'}


REMOTE_META = {'cTag': 'adDo1RDIzRUQzOTFCN0JFNUFEITExMDc5LjYzNjI4ODEyNDMwMjQ3MDAwMA',
               'createdBy': {'application': {'id': '44048800'},
                             'user': {'displayName': 'Finn Huckleberry',
                                      'id': '5d23ed391b7be5ad'}},
               'createdDateTime': '2017-04-26T13:52:07.867Z',
               'eTag': 'aNUQyM0VEMzkxQjdCRTVBRCExMTA3OS40',
               'id': '5D23ED391B7BE5AD!11079',
               'lastModifiedBy': {'user': {'displayName': 'CrossCloud CI Five',
                                           'id': '32326b368801ea5d'}},
               'lastModifiedDateTime': '2017-04-26T14:07:10.247Z',
               'name': 'beat',
               'parentReference': {'driveId': '5d23ed391b7be5ad',
                                   'id': '5D23ED391B7BE5AD!101',
                                   'name': 'root:',
                                   'path': '/drive/root:'},
               'remoteItem': {'fileSystemInfo': {'createdDateTime': '2017-04-26T13:51:08.3166667Z',
                                                 'lastModifiedDateTime':
                                                 '2017-04-26T13:51:08.3166667Z'},
                              'folder': {'childCount': 1,
                                         'folderView': {'sortBy': 'takenOrCreatedDateTime',
                                                        'sortOrder': 'ascending',
                                                        'viewType': 'thumbnails'}},
                              'id': '32326B368801EA5D!11755',
                              'parentReference': {'driveId': '32326b368801ea5d'},
                              'size': 0,
                              'webUrl': 'https://1drv.ms/u/s!AF3qAYg2azIy22s'},
               'webUrl': 'https://1drv.ms/u/s!AF3qAYg2azIy22s'}

PARAM_KEYS = 'func, expected, func_args'
PARAMS = [
    # item_endpoint
    (onedrive.item_endpoint,
        'drive/items/<item_id>/',
        {'item_id': '<item_id>'}),

    (onedrive.item_endpoint,
        'drives/12/items/9/',
        {'drive_id': 12, 'item_id': 9}),

    (onedrive.item_endpoint,
        'drive/items/9/',
        {'drive_id': None, 'item_id': 9}),

    # child_endpoint:
    (onedrive.child_enpoint,
        'drive/items/<parent_item_id>/children/<filename>/content',
        {'parent_item_id': '<parent_item_id>',
         'filename': '<filename>'}),

    (onedrive.child_enpoint,
        'drive/items/12/children/such_wow.txt/content',
        {'parent_item_id': 12,
         'filename': 'such_wow.txt'}),

    # child_endpoint with drive_id
    (onedrive.child_enpoint,
        'drives/<drive_id>/items/<parent_item_id>/children/<filename>/content',
        {'parent_item_id': '<parent_item_id>',
         'drive_id': '<drive_id>',
         'filename': '<filename>'}),

    # upload_session_endpoint
    (onedrive.upload_session_endpoint,
        'drive/items/<parent_item_id>:/<file_name>:/upload.createSession',
        {'parent_item_id': '<parent_item_id>',
         'filename': '<file_name>'}),
    (onedrive.upload_session_endpoint,
        'drive/items/42:/drug_money.txt:/upload.createSession',
        {'parent_item_id': 42,
         'filename': 'drug_money.txt'}),

    # upload_session_endpoint with drive_id
    (onedrive.upload_session_endpoint,
        'drives/<drive_id>/items/<parent_item_id>:/<file_name>:/upload.createSession',
        {'parent_item_id': '<parent_item_id>',
         'filename': '<file_name>',
         'drive_id': '<drive_id>'}),

    (onedrive.upload_session_endpoint,
        'drives/9999/items/42:/your_drug_money.txt:/upload.createSession',
        {'parent_item_id': 42,
         'filename': 'your_drug_money.txt',
         'drive_id': 9999
         }),
]


@pytest.mark.parametrize(PARAM_KEYS, PARAMS)
def test_functions(func, expected, func_args):
    """Test all onedrive functions functions."""
    assert expected == func(**func_args)


def test_onedrive_iterator_without_pagination():
    """Iterator must return values of first call if '@odata.nextLink' not returned.
    """

    api = Mock()
    response = Mock()
    response.json = Mock(return_value={'value': [1, 2, 3, 4]})
    api.get = Mock(return_value=response)

    iterator = onedrive.OneDriveIterator(api, 'xxx')

    assert list(iterator) == [1, 2, 3, 4]


def test_onedrive_iterator_with_pagination():
    """Iterator must return all values until is '@odata.nextLink' not returned.
    """
    def fake_responses():
        """Fake json responses which contains '@odata.nextLink' for first but call only.
        """
        if fake_responses.called == 0:
            res = {'value': [0, 1, 2, 3], '@odata.nextLink': 'blub'}
        else:
            res = {'value': [4, 5, 6, 7]}
        fake_responses.called += 1
        return res

    fake_responses.called = 0
    api = Mock()
    response = Mock()
    response.json = Mock(side_effect=fake_responses)
    api.get = Mock(return_value=response)

    iterator = onedrive.OneDriveIterator(api, 'xxx')

    assert list(iterator) == list(range(8))

    api.get.assert_any_call(endpoint='xxx', params={})
    api.get.assert_any_call(url='blub')

    assert api.get.call_count == 2


def test_onedrive_item_to_cc_props():
    """Api item meta must be converted into a props dict correctly.
    """
    pytest.skip('skip for now. Fix ASAP')
    props = onedrive.OneDrive.onedrive_item_to_cc_props(
        self={}, props={}, item=ITEM_META)
    assert props == {'_drive_id': '5d23ed391b7be5ad',
                     '_id': '5D23ED391B7BE5AD!101',
                     '_share_root': False,
                     IS_DIR: True,
                     'modified_date': dt.datetime(2017, 4, 26, 14, 7, 10, 247000,
                                                  tzinfo=pytz.utc),
                     'shared': False,
                     'size': 0,
                     VERSION_ID: IS_DIR}


def test_onedrive_remote_item_to_cc_props():
    """Item meta of a remote item should be converted into a props dict correctly.
    """

    pytest.skip('skip for now. Fix ASAP')
    props = onedrive.OneDrive.onedrive_item_to_cc_props(
        self={}, props={}, item=REMOTE_META)
    assert props == {'_drive_id': '32326b368801ea5d',
                     '_id': '32326B368801EA5D!11755',
                     '_remoteItem_id': '32326B368801EA5D!11755',
                     '_share_root': True,
                     IS_DIR: True,
                     'modified_date': dt.datetime(2017, 4, 26, 14, 7, 10, 247000,
                                                  tzinfo=pytz.utc),
                     'share_id': '32326B368801EA5D!11755',
                     'shared': False,
                     'size': 0,
                     VERSION_ID: IS_DIR}


def test_extract_ids_remote():
    """For remote items a drive_id and item id is required.
    """
    storage = Mock()
    drive_id, item_id = onedrive.OneDriveApi.extract_ids(
        storage, item_meta=REMOTE_META)
    assert drive_id == '32326b368801ea5d'
    assert item_id == '32326B368801EA5D!11755'


def test_extract_ids():
    """For items owned by the user, drive_id must be None, and item_id must be extracted.
    """
    storage = Mock()
    drive_id, item_id = onedrive.OneDriveApi.extract_ids(
        storage, item_meta=ITEM_META)
    assert drive_id == '5d23ed391b7be5ad'
    assert item_id == '5D23ED391B7BE5AD!101'


def test_get_shared_with_ids_private():
    """Test for get_shared_with_ids function if grantedTo is provided"""
    share_info = {'value': [{'grantedTo': {'user': {'id': 12}}}]}
    assert onedrive.get_shared_with_ids(share_info) == {12}


def test_not_shared_with_ids_private():
    """Test for get_shared_with_ids function if share_info is empty.
    """
    share_info = {'value': []}
    assert onedrive.get_shared_with_ids(share_info) == set()


def test_get_shared_with_ids_public():
    """Test for get_shared_with_ids function if grantedTo is provided"""
    share_info = {'value': []}
    assert onedrive.get_shared_with_ids(share_info) == set()


@pytest.fixture
def one_drive_storage():
    """Fixture of onedrive storage instance with a model set
    """
    def cred_reader(*args, **kwargs):
        """Fake storage_cred_reader"""
        print('reader')
        print(args)
        print(kwargs)
        return json.dumps({})

    def cred_writer(*args, **kwargs):
        """Fake storage_cred_writer"""
        print('writer')
        print(args)
        print(kwargs)

    storage = onedrive.OneDrive(event_sink=None,
                                storage_id='test',
                                storage_cred_reader=cred_reader,
                                storage_cred_writer=cred_writer)

    storage.model = bushn.IndexingNode('root', indexes=['_id'])
    folder_a = storage.model.add_child('folder_a', {'_id': '1'})
    folder_a.add_child('file_b', {'share_id': TEST_ID,
                                  'shared': True,
                                  '_shared_with': {'36e8c86a197301fc',
                                                   '32326b368801ea5d'}
                                  })

    return storage


@pytest.mark.manual
def test_monkey_in_tree():
    """Ask tester to share a folder with this account and ensure that the node is created.

    Note: The share needs to be accepted and added to the account being tested.
    """
    init_storage = init_onedrive()
    input(termcolor.colored('Please share a folder called "monkey" to this accout and hit [ENTER]',
                            'green', attrs=['blink', 'bold']))

    tree = init_storage.storage.model
    monkey = bushn.Node('monkey')

    assert monkey in tree, 'monkeys live in trees.'

    monkey = tree.get_node(['monkey'])
    logger.info(monkey.props)

    # assert some expected props
    assert monkey.props[IS_DIR] is True
    assert monkey.props['_remote_item'] is True
    assert monkey.props[VERSION_ID] == IS_DIR
    assert '_id' in monkey.props

    # test iter_share_roots
    share_roots = list(onedrive.iter_share_roots(init_storage.storage.model))
    assert monkey in share_roots


@pytest.mark.manual
def test_monkey_need_banana():
    """Ask tester to share a file with this account through the monkey share and test the resutls

    Note: The share needs to be accepted and added to the account being tested.
    """
    init_storage = init_onedrive()
    input(termcolor.colored('Please share a file called banana.txt in the monkey share with this'
                            'user and hit [ENTER]',
                            'green', attrs=['blink', 'bold']))

    tree = init_storage.storage.model
    logger.info(bushn.tree_to_str(tree))
    banana = tree.get_node(['monkey', 'banana.txt'])
    logger.info(banana.props['_remote_item'])
    assert '_id' in banana.props

    # In the OneDrive situation, shared is set for nodes
    # which are shared, and the account is the owner.

    assert banana.props['shared'] is False
    # this is a child of a remote_item, but itself is not marked as such
    # otherwise checking iter_share_roots() would create more deltas than
    # needed.
    assert banana.props['_share_root'] is False


@pytest.mark.manual
def test_monkey_eat_banana():
    """Ask tester to share a file with this account through the monkey share and test the resutls

    Note: The share needs to be accepted and added to the account being tested.
    """
    init_storage = init_onedrive()
    input(termcolor.colored('please place the banana file in, a new folder '
                            'called mouth inside the monkey folder.',
                            'green', attrs=['blink', 'bold']))

    tree = init_storage.storage.model
    logger.info(bushn.tree_to_str(tree))
    init_storage.storage.update()
    banana = tree.get_node(['monkey', 'mouth', 'banana.txt'])
    logger.info('\n' + bushn.tree_to_str(tree, '_id'))
    assert '_id' in banana.props
    with pytest.raises(KeyError):
        banana = tree.get_node(['monkey', 'banana.txt'])


@pytest.mark.manual
def test_monkey_lost_banana():
    """Ask tester to share a file with this account through the monkey share and test the resutls

    Note: The share needs to be accepted and added to the account being tested.
    """
    init_storage = init_onedrive()
    input(termcolor.colored('please place the banana file in, a new folder '
                            'called mouth inside the monkey folder.',
                            'green', attrs=['blink', 'bold']))

    tree = init_storage.storage.model
    logger.info(bushn.tree_to_str(tree))
    init_storage.storage.update()
    banana = tree.get_node(['monkey', 'mouth', 'banana.txt'])
    logger.info('\n' + bushn.tree_to_str(tree, '_id'))
    assert '_id' in banana.props
    with pytest.raises(KeyError):
        banana = tree.get_node(['monkey', 'banana.txt'])


# XXX: reactivate with authenticated Onedrive
# def test_get_shared_folders(one_drive_storage):
#     """Test calling the get_shared_folders method on one_drive_storage instance
#     """

#     shared_folder = one_drive_storage.get_shared_folders()
#     assert shared_folder[0].path == ['root', 'folder_a', 'file_b']
#     assert shared_folder[0].share_id == TEST_ID
#     assert shared_folder[0].sp_user_ids == {'36e8c86a197301fc',
#                                             '32326b368801ea5d'}


def test_get_update(mocker):
    """Assert share root is deleted from the tree."""
    def cred_reader(*args, **kwargs):
        """Fake storage_cred_reader"""
        print('reader')
        print(args)
        print(kwargs)
        return json.dumps({})

    def cred_writer(*args, **kwargs):
        """Fake storage_cred_writer"""
        print('writer')
        print(args)
        print(kwargs)

    with mocker.patch('jars.microsoft.onedrive.OneDrive._oauth_get_unique_id'):
        storage = onedrive.OneDrive(event_sink=None,
                                    storage_id='test',
                                    storage_cred_reader=cred_reader,
                                    storage_cred_writer=cred_writer)

    storage.model = bushn.IndexingNode(
        'root', indexes=['_id'], props={'_id': '0'})
    file_b = storage.model.add_child('file_b', {'share_id': TEST_ID,
                                                'shared': True,
                                                '_shared_with': {'36e8c86a197301fc',
                                                                 '32326b368801ea5d'},
                                                '_id': '2', 'is_dir': True, '_share_root': True
                                                })

    with mocker.patch('jars.microsoft.onedrive.OneDriveApi.get_delta',
                      side_effect=fake_get_delta), \
            mocker.patch('jars.microsoft.onedrive.iter_share_roots', return_value=file_b), \
            mocker.patch('jars.TreeToSyncEngineEngineAdapter') as mock_adapter:
        storage.get_update(storage.model, True)

    # pylint: disable=protected-access
    assert mock_adapter._on_delete.called_with(file_b)
    assert file_b not in storage.model


# pylint: disable=unused-argument
def fake_get_delta(delta_token, item_id, drive_id):
    """To mock the get_delta iterator and get desired returns."""
    item_list = []
    if item_id == '0':
        root = dict()
        root['id'] = item_id
        item_list.append(root)

        file_b = dict()
        file_b['name'] = 'file_b'
        file_b['id'] = '2'
        file_b['parentReference'] = {'id': '0'}
        file_b['deleted'] = {}
        file_b['cTag'] = 'b_ctag'
        file_b['lastModifiedDateTime'] = '4:30:21.447'
        item_list.append(file_b)
    else:
        raise HTTPError(
            'Recreating the error when accesing no longer existing file.')
    api = Mock()
    response = Mock()
    response.json = Mock(
        return_value={'value': item_list, '@delta.token': 'delta'})
    api.get = Mock(return_value=response)

    iterator = onedrive.OneDriveIterator(api, 'fake')
    iterator.last_response = mock.Mock(return_value={'@delta.token': ''})

    return iterator
