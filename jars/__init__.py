"""
CrossCloud Minimal Sync Requirements
************************************

Here are stated the minimum requirements needed for CrossCloud to be able to do sync
tasks with a cloud storage service.

Version Identifier
------------------

Each element needs to have a unique version identifier. This identifier changes when
the content of the element changes. It might also change if the metadata of this file
changes. Metadata can be for example if the item is shared with other users.


Directory Listing
-----------------

Endpoint to retrieve the file tree. The service **MUST** implement a method to list the
files available to sync (like the dir command in the DOS shell).
Stated below are the main methods for this task.

:meth:`~BasicStorage.get_tree`

:meth:`~BasicStorage.get_tree_children`


Download
--------

Endpoint to download a file from the storage via a stream. Comprehends the necessary
methods to download files from the cloud storage.
Stated below are the main methods for this task.

:meth:`~BasicStorage.open_read`


Upload/Modify
-------------

Endpoint to upload to a specified path via a stream. Comprehends the necessary methods
to perform upload and modifications tasks on the files.
Stated below are the main methods for this task.

:meth:`~BasicStorage.write`

:meth:`~BasicStorage.move`



Changes (Optional)
------------------

Server side changes should be available on a specific endpoint (e.g. long polling,
websockests, etc.).

For better understanding two examples:

1. The client fetches the current state of the storage with a directory listing and
then listens to changes via a specific endpoint.
2. The directory listing could also return a timestamp of this view and there is a second
endpoint where it is possible to fetch changes since a timestamp.


"""
import datetime
import logging
import pickle
import threading
import urllib.parse
from abc import ABCMeta, abstractmethod
from collections import namedtuple
from functools import wraps
from copy import copy
import json
import os

import atomicwrites
from requests_oauthlib import OAuth2Session
import bushn
from bushn import Node

MODEL_VERSION_KEY = 'model_version'

__version__ = '1.3.12'

IS_DIR = 'is_dir'
SIZE = 'size'
FILE_ID = 'file_id'
SHARED = 'shared'
SHARE_ID = 'share_id'
PUBLIC_SHARE = 'public_share'
VERSION_ID = 'version_id'
MODIFIED_DATE = 'modified_date'
FOLDER_VERSION_ID = 'is_dir'
DISPLAY_NAME = 'display_name'
METRICS = 'metrics'
CURSOR = 'cursor'
FILESYSTEM_ID = 'local'

# pylint: disable=too-many-instance-attributes

logger = logging.getLogger(__name__)


def remove_private_props(props):
    """ removes all _ keys from a dict """
    return {k: v for k, v in props.items() if not k.startswith('_')}


class CancelledException(Exception):
    """Thrown if a sync task is cancelled."""


class StorageError(Exception):
    """
    Base exception for storage Exceptions
    """

    def __init__(self, storage_id, origin_error=None, path=None):
        super().__init__()
        self.storage_id = storage_id
        self.error = origin_error
        self.path = path

    def __str__(self):
        return '{storage_id} -> {path}: {error}'.format(
            **self.__dict__)


class CertificateValidationError(StorageError):
    """The trust of a server certificate could not be established."""
    def __init__(self, storage_id, origin_error=None, path=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error, path=path)


class InvalidOperationError(StorageError):
    """Irrecoverable Error."""

    def __init__(self, storage_id, origin_error=None, path=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error, path=path)


class AccessDeniedError(InvalidOperationError):
    """Access to a resource is denied."""

    def __init__(self, storage_id, origin_error=None, path=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error, path=path)


class VersionIdNotMatchingError(StorageError):
    """Thrown if the given version id does not match with the executing part."""

    # pylint: disable=too-many-arguments
    def __init__(self, storage_id='<unknown_storage_id>', origin_error=None,
                 path=None, version_a="<unknown-version-id>",
                 version_b="<unknown-version-id> "):
        super().__init__(storage_id=storage_id, origin_error=origin_error, path=path)
        self.version_a = version_a
        self.version_b = version_b

    def __str__(self):
        return '{storage_id} -> {path}: {version_a} != {version_b}'.format(
            **self.__dict__)


class NoSpaceError(InvalidOperationError):
    """Thrown if there is no space avalaible (e.g. for an upload operation)."""

    def __init__(self, storage_id, origin_error, free_space):
        super().__init__(storage_id=storage_id, origin_error=origin_error)
        self.free_space = free_space


class EncryptedStreamError(InvalidOperationError):
    """Thrown if an encrypted file is written to a storage which is not supposed to have
     encrypted files."""


class CurrentlyNotPossibleError(StorageError):
    """Thrown if execution is currently not possible and may be possible in the future."""

    def __init__(self, storage_id, origin_error=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error)


class StorageOfflineError(CurrentlyNotPossibleError):
    """The storage is not reachable at the moment."""


class SevereError(StorageError):
    """Thrown if storage is not working appropriately (e.g. wrong API calls are made)."""

    def __init__(self, storage_id, origin_error=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error)


class AuthenticationError(SevereError):
    """Thrown if storage is not authenticated."""

    def __init__(self, storage_id, origin_error=None):
        super().__init__(storage_id=storage_id, origin_error=origin_error)


class UnavailableError(StorageError):
    """Thrown if storage is not reachable (HTTP 5xx)."""

    def __init__(self, storage_id, origin_error):
        super().__init__(storage_id=storage_id, origin_error=origin_error)


GrantUrl = namedtuple("GrantUrl", ['grant_url', 'check_function', 'csrf'])


# pylint: disable=R0904
class BasicStorage(metaclass=ABCMeta):
    """The abstract base class for storages in CrossCloud."""

    AUTH_NONE = 'AUTH_NONE'

    # service implements the static method authenticate()
    # and the static property grant_url. The property grant_url returns a GrantUrl with
    # which contains a url where the user can give his grant. And a regex, which should
    # match if the browser has redirected to correct target url.
    # afterwards authenticate() is should be called with that url.
    AUTH_OAUTH = 'AUTH_OAUTH'

    # credentials must implement authenticate() with the parameters url, username and
    # password.
    AUTH_CREDENTIALS = 'AUTH_CREDENTIALS'

    # credentials based storage that only operates on a fixed url (e.g. branded owncloud storage
    #  type. It must implement the same authenticate methods as auth_credentials and replace the
    #  url parameter with whatever it is bound to
    AUTH_CREDENTIALS_FIXED_URL = 'AUTH_CREDENTIALS_FIXED_URL'

    # A iterable of the supported auth mechanisms
    auth = []

    # The name, to be used in configs and so on
    storage_name = None
    storage_display_name = None

    # to be used if there is the need for a tempdir on the storage
    TEMPDIR = '.crosscloud-tmp'

    # pylint: disable=too-many-arguments
    def __init__(self, event_sink, storage_id, storage_cache_dir=None,
                 storage_cache_version=None, default_model=None):
        """ :param event_sink: In productive use this is the SyncEngine. Might be any
         other class implementing the event handling methods.
        :param storage_id: The storage_id of this storage.
        :param storage_cache_dir the directory to store model caches in
        :param storage_cache_version the version of the storage cache to load (older
        versions will be ignored if present = new model with new version will be generated
        :raise bushn.AuthenticationError in case the authentication data is wrong
        :raise
        """
        # settig storage id and events sink
        self.storage_id = storage_id
        self._event_sink = event_sink

        # The display name for the user, if available a username should be displayed, otherwise
        # default to email address.
        self._storage_user_name = None

        # setting cache dir (will be used to store model caches)
        self.cache_dir = storage_cache_dir

        # None permutable default model
        if default_model is None:
            default_model = Node(name=None)

        # read model cache if present and set it as internal model -> if no model is
        # present: generate new nodel using default node passed (e.g. Node,
        # or IndexedNode) dependent on what the specific service needs
        self.tree = load_model(cache_dir=self.cache_dir, default=default_model,
                               version=storage_cache_version)

        # private member for offline handling
        # DO NOT ACCESS DIRECTLY - use self.offline instead
        self._offline = False

        # directories to sync
        self.filter_tree = bushn.Node(name=None)

    @property
    def event_sink(self):
        """Return private event sink.

        We are deprecating `self._event_sink` in favour of `self.event_sink`
        see: https://gitlab.crosscloud.me/crosscloud/jars/issues/53
        """
        return self._event_sink

    @event_sink.setter
    def event_sink(self, event_sink):
        """Return private event sink.

        We are deprecating `self._event_sink` in favour of `self.event_sink`
        see: https://gitlab.crosscloud.me/crosscloud/jars/issues/53
        """
        self._event_sink = event_sink

    @property
    def model(self):
        """Return the internal tree.

        This is here during the transistion away from model:
        see: https://gitlab.crosscloud.me/crosscloud/jars/issues/53
        """
        return self.tree

    @model.setter
    def model(self, value):
        self.tree = value

    @staticmethod
    def authenticate(**kwargs):
        """  If OAuth is a possible authentication method, this function needs to return
        the grant url.

        :param storage_cred_write: a method to write the authentication data to
        :param ignore_warnings: Ignores warnings if there are any
        :return: a list of warnings. If there are any, the auth process is not completed
         and needs to be redone with ignore_warnings set to True.
        """

    @abstractmethod
    def start_events(self):
        """Starts the delivery of events.

        Storage should be properly updated by calling update before calling this method.
        """

    @abstractmethod
    def stop_events(self, join=False):
        """Stop the delivery of events.

        :param join: if true this methods should blocks and joins executing thread.
        """

    @abstractmethod
    def make_dir(self, path):
        """Create a directory on the storage, implicitly creates all parents. No
        exceptions are thrown if the parent already exists.

        :param path: A path as list of strings.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        :returns: returns the folders version id (normally `bushn.FOLDER_VERSION_ID`).
        """

    @abstractmethod
    def open_read(self, path, expected_version_id):
        """Download a file to the local filesystem.
        Uses HTTP request
        with If-Match header with the entity tags of the files it's looking for.

        The version id of the file requested for download should be included in the
        request, in case there's an id missmatch the download fails.

        :param path: a path represented by a list of strings
        :param expected_version_id: the known version id of the metadata. If not None, it
         will be checked before opening the file. If the version id is not matching, it
         will throw a VersionIdNotMatchingError.
        :returns: file like object representing of the given file on storage.
        :throws: :class:`VersionIdNotMatchingError` if version id of file does not match.

        If the **expected_version_id** does not match the id of the file in the
        specified path this exception is thrown.

        :throws: :class:`FileNotFoundError` if file does not exist on storage.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`InvalidOperationError` if file is not on storage.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        """

    @abstractmethod
    def write(self, path, file_obj, original_version_id=None, size=0):
        """Write a file to the given storage. Uses a HTTP request with If-Match header
        with the entity tags of the files.
        It implicitly creates all intermeditate folders if necessary.

        Same as with the uploads, Version Headers should be included in the request,
        if the versions differ the upload fails. Being able to continue an upload that has
        been interrumpted for whatever reason is also valuable, supporting fragmented
        uploads allowing to query only the missing parts instead of the whole file makes
        the service more efficient.

        :param size: for some storages this is needed to store the data
        :param original_version_id: the known version id of the metadata. If not None, it
         will be checked before the file is then copied to the final destination.
         If the version id is not matching, it will throw a VersionIdNotMatchingError.
        :param file_obj: The file object where the file is read from
        :param path: the path is a list of strings
         copy, a file object as target and a chunk size.
        :throws: :class:`FileNotFoundError` if file does not exist.
        :throws: :class:`VersionIdNotMatchingError` if version id of source has changed.
        :throws: :class:`NoSpaceError` if not enough space available.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        """

    @abstractmethod
    def move(self, source, target, expected_source_vid, expected_target_vid):
        """Move a file or folder from one path to another. Should be as atomic as possible.
        There  is no difference between a file or a directory. All folders necessary for
        the new location are created implicitely. In case of a folder its content is moved
        as well.

        Same as with the uploads, Version Headers should be included in the request, if
        the versions differ the move fails.


        :param source: a path represented by a list of strings
        :param target: a path represented by a list of strings
        :param expected_source_vid: the expected version id of the source
        :param expected_target_vid: if the target already exists, this is the version id
        of the file to be replaced
        :throws: :class:`FileNotFoundError` if source file does not exist on storage.
        :throws: :class:`VersionIdNotMatchingError` if version id of source has changed.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        """

    @abstractmethod
    def delete(self, path, original_version_id):
        """Delete a file or folder on the remote storage

        If a directory, all is recursive deleted. If a file, it will delete it.

        :param path: a list of strings
        :param original_version_id: the known version id of the metadata.

        If not None, it will be checked before the file is then deleted. If the version id
        is not matching, it should throw a VersionIdNotMatchingError.

        :throws: :class:`VersionIdNotMatchingError` if version id differs.
        :throws: :class:`FileNotFoundError` if file does not exist on storage.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        """

    @abstractmethod
    def update(self):
        """Updates storage and sets state for upcoming events.

        # TODO: This method needs better documentation
        """

    def get_tree(self, cached=False):
        """This will fetch and return the full tree and its metadata.

        Should return the root node for the tree. This basic implementation will use`get_children`.
        ..Note. get_tree should never modify the storage's state.

        if cached is False, no internal state may be used to create the tree. Else a filtered copy
        of self.model can be returned

        :param cached: whether to use internal state to return tree.
        :param parent: The path from which children are returned.
            If None its done from the root.

        :throws: :class:`InvalidOperationError` if no subtree with parent exists.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        :returns: :class:`bushn.Node` object
        """
        # pylint:disable=unused-argument

        root = bushn.Node(name=None)

        working_stack = [root]

        while working_stack:
            parent = working_stack.pop()
            try:
                # children_to_add [(recurse, child)]
                filter_node = self.filter_tree.get_node(parent.path)

                # if we have a filter node see if it has children, if yes, only deliver
                # non-dirs if children is set to true
                if filter_node.children:
                    children_to_add = \
                        [(child, True)
                         for child in self.get_tree_children(parent.path)
                         if not child[1]['is_dir'] or filter_node.has_child(child[0])]
                else:
                    # it has no children just recurse
                    children_to_add = \
                        [(child, True) for child in self.get_tree_children(parent.path)]
            except KeyError:
                children_to_add = \
                    [(child, True) for child in self.get_tree_children(parent.path)]

            for (name, props), recurse in children_to_add:
                child = parent.add_child(name, props)

                if props.get('is_dir') and recurse:
                    working_stack.append(child)

        return root

    @abstractmethod
    def get_tree_children(self, path):
        """
        Works the same as :meth:`get_tree` but for a specified folder (not recursive).
        This should be implemented stateless and with speed in mind i.e. do not attempt
        to fetch whole subtrees of a given path. Should return a iterable of tuples with
        the filename as a string in and the metadata as a dict containing the meta data
        for all children of the path.

        :param path: path as list of strings
        :throws: :class:`FileNotFoundError` if no subtree for path exists.
        :throws: :class:`CurrentlyNotPossibleError` if operation can currently not be
            executed.
        :throws: :class:`UnavailableError` if storage is not reachable.
        :throws: :class:`AuthenticationError` if storage is not authenticated properly.
        :throws: :class:`SevereError` if storage is not valid.
        :returns: iterable of tuple of path and prop dictionaries
        """
        raise NotImplementedError()

    #: supports_sharing_link is set to True if creation of public sharing
    #: links are supported
    supports_sharing_link = False

    def create_public_sharing_link(self, path):
        """ Creates public sharing link of file with path.

        :param path: from which public sharing link should be created
        :return: URL of public sharing link.
        :throws: :class:`StorageError` if public sharing link can not be created.
        :throws: :class:`NotImplementedError` if public sharing links are not supported.
        """
        raise NotImplementedError

    #: is set to True if creation of web links are supported
    supports_open_in_web_link = False

    def create_open_in_web_link(self, path):
        """ Creates web link of file with path.

        This is used to display the original item to the user via browser.

        :param path: from which web link should be created
        :return: URL of a private web link
        :throws: :class:`StorageError` if web sharing link can not be created.
        :throws: :class:`NotImplementedError` if web links are not supported.
        """
        raise NotImplementedError

    #: supports_serialization is True if this functionality is supported
    supports_serialization = False

    def serialize(self):
        """
        Serializes model persistently.
        """
        # saving the model to the configured cache directory (overwriting old one)
        save_model(model=self.model, cache_dir=self.cache_dir)

    @abstractmethod
    def clear_model(self):
        """Reset the internal model of the storage.
        """
        pass

    def get_internal_model(self):
        """Return the root node of the current internal model.

        NOTE!! This method is only for testing purposes NOTE!!
        This method returns the internal model of the storage service"""
        return self.model

    @abstractmethod
    def check_available(self):
        """ This method should check if the storage is available.

        Since a storage should be always instantiable, even if it can't be reached,
        this method is used to check if the storage is online and can be accessed with
        the current credentials.

        :except: :class:`StorageOfflineError`, :class:`AuthenticationError`
        """
        pass

    @property
    def offline(self):
        """
        Returns the current connections state of the storage
        """
        return self._offline

    @offline.setter
    def offline(self, offline):
        """
        Sets the current connections state and triggers the events

        :param offline: True if the storage is offline
        """
        if offline:
            # storage is offline -> trigger event if not already triggered
            if not self._offline:
                self._event_sink.storage_offline(storage_id=self.storage_id)
                self._offline = True
        else:
            # storage is online -> trigger event if not already triggered
            if self._offline:
                self._event_sink.storage_online(storage_id=self.storage_id)
                self._offline = False

    def get_shared_folders(self):
        """Return the list of :class:`bushn.SharedFolder`
        on this storage """
        # pylint: disable=no-self-use
        return []

    @property
    def storage_user_name(self):
        """Return a username for the current storage."""
        if self._storage_user_name is None:
            self.storage_user_name = self.create_user_name()
        return self._storage_user_name

    @storage_user_name.setter
    def storage_user_name(self, value):
        """Set a users name."""
        self._storage_user_name = value

    def create_user_name(self):
        """Creates the username with the proper structure.

        If a username is available this would be the prefered option, else email address.
        """
        pass


# This tuple is used for storing information about a shared folder
SharedFolder = namedtuple('SharedFolder', ['path', 'share_id', 'sp_user_ids'])
""" A Shared folder returned by get_shared_folders

:var path: The path to this folder
:var share_id: Identifier for shared item which is the same for two users who share this item.
:var sp_user_ids: A list of user ids from the perspective of the storage provder.
"""


def error_mapper(mapper, operation=None):
    """
    Executes method while mapping error after execution error.
    """

    def ex_map_decorator(func):
        """
        Map error after execution
        """

        @wraps(func)
        def execute_with_error_mapping(storage_instance, *args, **kwargs):
            """
            Wrapping function.
            """
            try:
                return func(storage_instance, *args, **kwargs)
            except Exception as error:  # pylint: disable=broad-except
                handled = mapper(error=error,
                                 operation=operation,
                                 storage_id=storage_instance.storage_id)
                if not handled:
                    raise error
                else:
                    return handled

        return execute_with_error_mapping

    return ex_map_decorator


class OAuthApi(metaclass=ABCMeta):
    """Baseclass implementing oauth2 for storages for requests"""

    # yes there are no members, they are ment to be set
    # pylint: disable=no-member,abstract-method

    auth = [BasicStorage.AUTH_OAUTH]

    def __init__(self, event_sink, storage_id, storage_cred_reader, storage_cred_writer,
                 storage_cache_dir=None, storage_cache_version=None,
                 default_model=None):
        # pylint: disable=too-many-arguments
        super().__init__(event_sink=event_sink, storage_id=storage_id,
                         storage_cache_dir=storage_cache_dir,
                         storage_cache_version=storage_cache_version,
                         default_model=default_model)

        self.oauth_session = OAuth2Session(
            self.client_id,
            token=json.loads(storage_cred_reader()),
            token_updater=lambda token: storage_cred_writer(json.dumps(token)),
            auto_refresh_kwargs={'client_id': self.client_id,
                                 'client_secret': self.client_secret},
            auto_refresh_url=self.token_url)

    @classmethod
    def authenticate(cls, grant_url, callback_url, force=False):
        """ the second part of the auth process takes place here """
        # pylint: disable=arguments-differ, unused-argument
        oauth_session = grant_url.csrf
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        # Fetch the access token
        token = oauth_session.fetch_token(cls.token_url, client_secret=cls.client_secret,
                                          authorization_response=callback_url)
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

        # check duplicate account
        unique_id = cls._oauth_get_unique_id(oauth_session)

        credentials = json.dumps(token)

        return ([], credentials, unique_id)

    @classmethod
    @abstractmethod
    def _oauth_get_unique_id(cls, oauth_session):
        """ This will be called to get a unique identifier for the storage, the same
        identifier must be used, if share lists are exposed """
        raise NotImplementedError

    @classmethod
    def grant_url(cls):
        """Return the GrantUrl named tuple for the storage.

        This tuple contains all vaules required for the first phase of the oauth process.
        """

        oauth_session = OAuth2Session(cls.client_id, scope=cls.scope,
                                      redirect_uri=cls.redirect_uri)

        # Redirect user to Google for authorization
        authorization_url, _ = oauth_session.authorization_url(
            cls.authorization_base_url)

        # offline for refresh token
        # force to always make user click authorize
        # access_type="offline",
        # approval_prompt="force")

        def check_function(url):
            """Parse if the url contains all the expected callback fields.

            This if cascade is a bit convoluted. Originally the check only entailed
            checking if state is in the query. However for some storages, error can also
            be present.
            TODO: Refactor so each storage can provide its own check_function.
            """
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            if 'error' in query:
                return False

            elif 'state' in query:
                return True

            return False

        return GrantUrl(authorization_url, check_function, oauth_session)

# pylint: disable=abstract-method


class OAuthBasicStorage(OAuthApi, BasicStorage):
    """Combination of OAuthApi and BasicStorage used as a base for many storages.
    """
    pass
# pylint: enable=abstract-method


def load_model(cache_dir, default=None, filename='storage_model.p', version=None):
    """
    unpickels the mode from the cache_dir joined with the filename

    :param cache_dir: directory to models
    :param default: def value for if cannot be loaded
    :param filename: filename of the model
    :param version: if only a specific version of the model shall be loaded,
    this checks for a match, if they don't
     match -> return default
    """
    if cache_dir is None:
        return default

    model_cache_path = os.path.join(cache_dir, filename)
    logger.info('Loading model from %s', model_cache_path)
    try:
        # reading file and de-pickling (unmarshaller)
        with open(model_cache_path, "rb") as file:
            model = pickle.load(file)

        # checking version
        if version is not None:
            # if versions do not match -> returning default value
            model_version = model.props.get(MODEL_VERSION_KEY, '0')
            if model_version != version:
                return default

        # returning read model
        return model
    except (IOError, EOFError, FileNotFoundError, AttributeError, TypeError):
        logger.info('cannot read model', exc_info=True)
        return default


def save_model(model, cache_dir, filename='storage_model.p', version=None):
    """
    Serializes model persistently.
    """
    try:
        # creating model path and dirs if not present
        model_cache_path = os.path.join(cache_dir, filename)
        os.makedirs(cache_dir, exist_ok=True)

        # writing in version if set
        if version is not None:
            model.props[MODEL_VERSION_KEY] = version

        # pickling out model to file
        with atomicwrites.atomic_write(model_cache_path, mode='wb',
                                       overwrite=True) as file:
            pickle.dump(model, file)
    except IOError:
        logger.exception('cannot write pickle file')


def casefold_path(path):
    """
    Normalizes the given path with unicode NFC and lower case

    :param path: the path
    :return: the normalized path
    """
    new_path = []
    for elem in path:
        new_path.append(elem.casefold())
    return new_path


class StorageMetrics:
    """
    Storage Metrics
    """

    def __init__(self, storage_id, free_space, total_space=None, display_name=None):
        if total_space is None:
            total_space = free_space

        self.storage_id = storage_id
        self._total_space = total_space
        self._free_space = free_space
        self.offline = False
        self.valid_auth = True
        self.display_name = display_name
        self.valid_encryption_setting = True

    @property
    def free_space(self):
        """ the free space of a storage
        """
        return self._free_space

    @free_space.setter
    def free_space(self, value):
        """ free space setter which takes the max and min space into account
        """
        if value > self._total_space:
            logger.warning("Metrics for %s: "
                           "Trying to set a free space greater than the total space "
                           "%d > %d", self.storage_id, value, self._total_space)
            value = self._total_space
        if value < 0:
            logger.warning("Metrics for %s: "
                           "Trying to set a negative free spac"
                           "%d < 0", self.storage_id, value)
            value = 0
        self._free_space = value

    @property
    def total_space(self):
        """ getter for the total space of a storage
        """
        return self._total_space

    def __repr__(self):
        """ Representation of metrics """
        return "<StorageMetrics id={} free space: {:2.2f}MB total space: {:2.2f}MB>". \
            format(self.storage_id,
                   self._free_space / (1024 * 1024),
                   self._total_space / (1024 * 1024))

    def update(self, other):
        """
        Updates metrics.
        """
        self._free_space = other.free_space
        self._total_space = other.total_space


class PollingScheduler(threading.Thread):
    """ Helper class for pollers, which helps to be cancelable"""

    # pylint: disable=too-many-arguments
    def __init__(self, interval, target=None, target_args=(), target_kwargs=None,
                 offline_callback=None):
        """
        Scheduled method execution

        :param interval: sleep between two executions
        :param target: target function pointer
        :param target_args: target arguments
        :param target_kwargs: target keyword argument
        :param offline_callback: triggered with parameter true if call was successful
                                 and false if it failed
        """
        super().__init__(daemon=True)
        if target_kwargs is None:
            target_kwargs = {}
        self.target = target
        self.target_args = target_args
        self.target_kwargs = target_kwargs
        self.stop_event = threading.Event()
        self.interval = interval
        self.offline_callback = offline_callback

    def stop(self, join=False, timeout=None):
        """ sets the stop flag  """
        self.stop_event.set()
        if join:
            self.join(timeout)

    def start(self):
        """ resets the stop flag """
        if not self.is_alive():
            self.stop_event.clear()
            return super().start()

    def run(self):
        """ checks every interval """
        while True:
            try:
                self.target(*self.target_args, **self.target_kwargs)
            except AuthenticationError:
                logger.info("Authentication data is invalid")
            except BaseException:
                logger.info("Error while polling for changes", exc_info=True)
                # -> offline
                if self.offline_callback:
                    self.offline_callback(True)
            else:
                # everything ok so we are online
                if self.offline_callback:
                    self.offline_callback(False)
            self.stop_event.wait(self.interval)

            if self.stop_event.is_set():
                logger.debug("Stopped poller")
                break


PROPS_TYPE_MAP = [('is_dir', bool),
                  ('shared', bool),
                  ('modified_date', datetime.datetime),
                  ('version_id', object),
                  ('size', int)]


def check_storage_properties(props):
    """ this function checks if the properties are compliant with the sync engine,
    but it will not indicate, if there are too many keys present """
    for key, tipe in PROPS_TYPE_MAP:
        value = props.get(key)
        if not isinstance(value, tipe):
            logger.info('Property failed validation: %s is %s not %s', key, type(value), tipe)
            return False
    return True


class TreeToSyncEngineEngineAdapter(object):
    """ Adapter which translates tree events to :class:`cc.syncengine.SyncEngine` calls"""

    def __init__(self, node, sync_engine, storage_id):
        """
        :param node: A root :class:`bushn.Node`, where all the events are coming from
        :param sync_engine: :class:`cc.syncengine.SyncEngine` where all the events are
        emitted to
        :param storage_id: a string representing the storage
        """

        #: If the events should be emitted, with this property that can be disabled
        self.emit_events = True

        self._sync_engine = sync_engine
        self._node = node
        self._storage_id = storage_id

    def __enter__(self):
        self._node.lock.acquire()
        self._register_signals()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._disconnect_signals()
        self._node.lock.release()

    def _register_signals(self):
        """ registeres all signal to the members """
        self._node.on_update.connect(self._on_update)
        self._node.on_delete.connect(self._on_delete)
        self._node.on_create.connect(self._on_create)
        self._node.on_moved.connect(self._on_moved)
        self._node.on_renamed.connect(self._on_renamed)

    def _disconnect_signals(self):
        """ registeres all signal to the members """
        self._node.on_update.disconnect(self._on_update)
        self._node.on_delete.disconnect(self._on_delete)
        self._node.on_create.disconnect(self._on_create)
        self._node.on_moved.disconnect(self._on_moved)
        self._node.on_renamed.disconnect(self._on_renamed)

    def transform_path(self, node):
        """This function is meant to be overridden by a subclass if the representation
        of the paths within the storage are different then the ones used in the tree """
        # this function is here to be overwritten
        # pylint: disable=no-self-use
        return copy(node.path)

    def _on_update(self, node, other):
        # ignore updates on root
        if not node.parent:
            return

        # This ensures that all node/storage properties within a given path
        # exist before triggering an "update" event.
        if not check_storage_properties(node.props):
            logger.info('Properties are not compliant %s, %s', node.path, node.props)
            return

        logger.debug('_on_update: %s', node.path)
        new_props = dict(node.props)
        new_props.update(other)
        logger.debug('modify from %s to %s', node.props, new_props)
        self._sync_engine.storage_modify(
            storage_id=self._storage_id, path=self.transform_path(node),
            event_props=remove_private_props(new_props))

    def _on_delete(self, node):
        logger.debug('_on_delete: %s', node.path)
        self._sync_engine.storage_delete(
            storage_id=self._storage_id, path=self.transform_path(node))

    def _on_create(self, node):
        # This ensures that all node/storage properties within a given path
        # exist before triggering an "create" event.
        if not check_storage_properties(node.props):
            logger.info('Properties are not compliant %s, %s', node.path, node.props)
            return

        logger.debug('_on_create: %s: %s', node.path, node.props)
        self._sync_engine.storage_create(
            storage_id=self._storage_id, path=self.transform_path(node),
            event_props=remove_private_props(node.props))

    def _on_moved(self, node, old_parent):
        old_path = self.transform_path(old_parent) + [self.transform_path(node)[-1]]
        logger.debug('move from %s to %s', old_path, node.path)
        self._sync_engine.storage_move(storage_id=self._storage_id,
                                       source_path=old_path,
                                       target_path=self.transform_path(node),
                                       event_props=remove_private_props(node.props))

    def _on_renamed(self, node, old_name):
        # TODO: this is not clean, since we are not able to use a possible old name (tran. path)
        new_path = self.transform_path(node)
        old_path = new_path[:-1] + [old_name]
        logger.debug('rename from %s to %s', old_path, new_path)
        self._sync_engine.storage_move(storage_id=self._storage_id,
                                       source_path=old_path,
                                       target_path=new_path,
                                       event_props=remove_private_props(node.props))


# pylint: disable=invalid-name
registered_storages = []
