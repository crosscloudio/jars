"""
Utilities for all storages which are HTTP based on requests.
"""
import logging
import functools

import requests.exceptions

import jars


logger = logging.getLogger(__name__)
##################################################################
# !!! HTTP Standard error map, copy this before extending it !!! #
##################################################################
ERROR_MAP = {
    401: jars.AuthenticationError,  # Unauthenticated
    403: jars.AccessDeniedError,  # Forbidden
    404: FileNotFoundError,  # File Not Found
    412: jars.VersionIdNotMatchingError,  # Precondition Failed
    429: jars.CurrentlyNotPossibleError,  # too many requests
    423: jars.CurrentlyNotPossibleError,  # locked -> try again later
    502: jars.CurrentlyNotPossibleError,
    503: jars.CurrentlyNotPossibleError,
    504: jars.CurrentlyNotPossibleError}


def error_mapper(fun, error_map=ERROR_MAP):
    """ A decorator which maps the class:`requests.exceptions.HTTPError`
     from requests to jars exceptions. class:`requests.exceptions.Timeout`
     exceptions are handled as well.  """

    # its fine, we do only read-only from ERROR_MAP
    # pylint: disable=dangerous-default-value

    @functools.wraps(fun)
    def new_fun(*args, **kwargs):
        """ function wrapper """
        try:
            return fun(*args, **kwargs)
        except requests.exceptions.HTTPError as exception:
            if exception.response.status_code in error_map:
                raise error_map[exception.response.status_code](
                    exception.response.text)
            else:
                raise
        except requests.exceptions.Timeout:
            logger.debug('Timeout exception')
            raise jars.CurrentlyNotPossibleError('')
        except requests.exceptions.ConnectionError as ecx:
            logger.debug(ecx)
            raise jars.CurrentlyNotPossibleError('')

    return new_fun
