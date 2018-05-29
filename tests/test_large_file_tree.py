"""Based on CC-527 this module test large trees on each jar.

These are set to manual since they take long and currently still fail often.
currently running this on onedrive for instance takes about 10 minutes.

To test onedrive for instance run:
    `py.test -k 'test_with_large_amount_of_files[onedrive' --manual -s`

Notes:
    - macOs: upper bound set by `OSError file too long`

TODO: are random sleeps needed to prevent hitting rate limits?
"""
import copy
import io
import logging
import math
import random
import string
import os

import pytest

import jars

from .test_storage import delete_all_files

logger = logging.getLogger(__name__)
# pylint: disable=invalid-name
MAX = 100
PARAM_KEYS = 'folder_width, folder_depth, file_count'
PARAMS = [(1, 1, 1),  # simple
          (0, 1, MAX),  # go wide
          (1, MAX, 0),  # go deep
          (2, 3, 3)]  # other


def make_files(storage, path, num_files, min_file_size=1024, max_file_size=4096):
    """Fill a given path with a certain number of randomly named files.

    :param storage: the instance of the storage provider
    :param path: the path of the folder the files should be written to
    :param num_files: the number of files to be written
    :param min_file_size: the minimum file size of a file (default 1KB)
    :param max_file_size: the maximum file size of a file (default 4KB)
    :return: the number of files written
    """
    logger.info("Creating %d files in '%s'", num_files, path)
    for _ in range(num_files):
        size = random.randint(min_file_size, max_file_size)
        content = io.BytesIO(os.urandom(size))
        name = "".join(random.sample(string.ascii_letters, 10))
        full_path = path + ["{}.bin".format(name)]
        logger.debug("Writing '%s' with size %d in '%s'...", name, size, full_path)
        storage.write(full_path, content, size=size)
        logger.info("Wrote '%s'", full_path)
    return num_files


@pytest.mark.skip
def test_get_tree_children_with_many_files(init_storage_test_without_files_events,
                                           num_files=300):
    """Upload `num_files` to root call `get_tree_children` and check result"""
    storage = init_storage_test_without_files_events.storage
    tidy_up(storage, event_sink=storage.event_sink)

    path = []
    make_files(storage, path, num_files=num_files, min_file_size=8, max_file_size=16)
    children = storage.get_tree_children(path)
    assert len(list(children)) == num_files


def random_names(count):
    """Return random names for items in a tree.

    :param count: number of names to generate.
    :return: list of random names.
    TODO: use unicode?
    """
    return ["".join(random.sample(string.ascii_letters, 8)) for n in range(count)]


def tidy_up(storage, event_sink):
    """Deletes all files on storage and tidies up a single test."""

    logger.debug('*************** TYDING UP TEST ffor %s'
                 '***********************', storage)

    delete_all_files(storage=storage, event_sink=event_sink)
    storage.stop_events(join=True)

    logger.debug('*************** TYDIED UP TEST for %s'
                 '***********************', storage)


def populate_with_items(storage, root, folder_width=2, folder_depth=1, file_count=2):
    """Create a random hierarchy of files and folders in a given path.

    :param storage: instance of the storage provider
    :param root: the root/base folder the hierarchy should be created in (auto created).
    :param folder_width: the number of folders in the root
    :param folder_depth: the number of child folders per folder
    :param files: the number of files that should be created in _every_ folder (except root)
    :return: the number of files created
    """

    if root:
        logger.debug("Creating root at '%s'", root)
        storage.make_dir(root)

    path = copy.copy(root)
    make_files(storage, path, file_count)

    if folder_depth == 0:
        return

    # create the width
    for folder in random_names(folder_width):
        path.append(folder)
        # logger.info('### path: %s', path)
        storage.make_dir(path)

        logger.debug("Created folder '%s'", path)

        # create the depth
        populate_with_items(root=path,
                            storage=storage,
                            folder_width=folder_width,
                            folder_depth=folder_depth - 1,
                            file_count=file_count)


def node_count(folder_width, folder_depth):
    """Calculate the number of nodes of a k-ary tree.

    https://en.wikipedia.org/wiki/K-ary_tree
    k = folder_width
    j = folder_depth
    """
    if folder_width == 1:
        # prevent div by zero error
        return folder_depth + 1

    enumerator = folder_width**(folder_depth + 1)
    denominator = folder_width - 1
    result = math.ceil(enumerator / denominator)

    # subtract 1 for root node
    return abs(result - 1)


@pytest.mark.parametrize(PARAM_KEYS, PARAMS)
@pytest.mark.manual
def test_with_large_amount_of_files(init_storage_test_without_files_events,
                                    folder_width, folder_depth, file_count):
    """Ensure the storage provider is able to handle a large amount of files."""
    storage = init_storage_test_without_files_events.storage
    before = len(storage.get_internal_model())

    populate_with_items(storage,
                        root=['base'],
                        folder_width=folder_width,
                        folder_depth=folder_depth,
                        file_count=file_count)

    # calculate the number of expected nodes
    folder_nodes = node_count(folder_width=folder_width,
                              folder_depth=folder_depth)

    file_nodes = folder_nodes * file_count
    expected_nodes = folder_nodes + file_nodes

    root_node = storage.get_tree(cached=False).get_node(['base'])
    # print('+'*15 +'\n')
    # print(bushn.tree_to_str(root_node))
    # print('\n'+'+'*15)
    assert len(root_node) == expected_nodes
    storage.delete(['base'], original_version_id=jars.FOLDER_VERSION_ID)

    root_node = storage.get_tree(cached=False)
    assert before == len(root_node)
