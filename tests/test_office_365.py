"""Test the setup of microsoft office 365 group storage and api."""
from unittest import mock
import oauthlib
import pytest
from jars import microsoft
import bushn

from tests.setup import SetupStorage


class Office365Setup(SetupStorage):
    """Properties required to initialize a Office365 test."""
    STORAGE_CLASS = microsoft.office365.Office365Groups
    NAME = 'office365'
    NODE_CLASS = bushn.IndexingNode
    ROOT_INIT_PARAMS = {'name': None,
                        'indexes': ['_id']
                        }


def test_correct_api_class(office365_fixture):
    """Esure that the api used by office_356 is correct.

    Note this tests the init_office365_groups more than anything else.
    """
    assert isinstance(office365_fixture.storage.api,
                      microsoft.microsoft_graph.Office365Api)


def test_token_refresh(office365_fixture):
    """Esure that the token refresh process works as expected.

    Patch first call to to session.get to raise TokenExpiredError, which triggers the
    token checker in order to ensure that token we get from the server contains
    a refresh_token and the correct scope.
    """
    pytest.skip('')
    final_url = 'https://crosscloud.me/'
    api = office365_fixture.storage.api
    api_class = office365_fixture.storage.API_CLASS

    def token_checker(token):
        """Ensure refesh_token and scope are correct."""
        assert 'refresh_token' in token
        returned_scope = [entry.lower() for entry in token['scope']]
        assert set(api_class.scope) == returned_scope

    # patch api.session._client.add_token() to first raise TokenExpiredError and
    # then retutn a valid url
    # pylint: disable=protected-access
    client_class = api.session._client.__class__
    side_effects = [oauthlib.oauth2.rfc6749.errors.TokenExpiredError, (final_url, '', {})]
    client_patch = mock.patch.object(client_class, 'add_token', side_effect=side_effects)

    # patch api.session.token_updater to check the returned token instead of writing it
    # to disk.
    session_class = api.session.__class__
    session_patch = mock.patch.object(session_class, 'token_updater',
                                      return_value=token_checker,
                                      create=True)
    with client_patch, session_patch:
        api.session.token_updater = token_checker
        response = api.session.get('https://action0.com')

    assert response.url == final_url
