"""tests the basic file system implementation"""
# for tests we disabled that, otherwise fixtures are making trouble
# pylint: disable=redefined-outer-name

import os
import io
import logging
from unittest.mock import Mock
import shutil
import tempfile

import pytest

from tests.setup import SetupStorage
from jars import FILESYSTEM_ID, InvalidOperationError, CurrentlyNotPossibleError
from jars.fs.filesystem import fs_to_cc_path, cc_path_to_fs
from jars.fs import Filesystem
from jars.utils import WriteToTempDirMixin

if os.name == 'nt':
    from jars.fs.windows import WindowsFileReader

TEST_STRING = b'123' * 32 * 1025


class FileSystemSetup(SetupStorage):
    """Properties required to initialize a FileSytem test."""
    STORAGE_CLASS = Filesystem
    NAME = 'filesystem'

    @property
    def init_params(self):
        """Parameters used to initialize the the storage"""

        return {'storage_id': self.NAME,
                'event_sink': self.mock_event_sink,
                'root': None}


@pytest.mark.skipif(os.name != 'nt', reason='windows only test')
def test_fs_to_cc_path_parent_dir():
    """Checks if elements with '..' are rejected. But names with '..' should be ok"""

    assert fs_to_cc_path(r'c:\hello\123', r'c:\hello') == ['123']

    assert fs_to_cc_path(r'c:\hello\123..a', r'c:\hello') == ['123..a']

    with pytest.raises(AssertionError):
        fs_to_cc_path(r'c:\hello\..', r'c:\hello')


@pytest.mark.skipif(os.name != 'nt', reason='windows only test')
def test_cc_path_to_fs_root():
    """
    checks if elements with '..' are rejected. But names with '..' should be ok
    """

    assert cc_path_to_fs([], r'c:\hello') == 'c:\\hello\\'


def test_write_on_deleted_file(tmpdir):
    """Tests if file with the same name can be created when it has been deleted before.

    This is especally problematic on Windows.
    """
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # 1. create the testfile
    testfile = tmpdir.join('testfile')
    testfile.write('hello123')

    filesystem = Filesystem(str(tmpdir), Mock(), FILESYSTEM_ID)

    file_obj = filesystem.open_read(['testfile'])

    # for debugging open in explorer
    # os.startfile(str(tmpdir))
    # time.sleep(10)

    # delete the file
    os.unlink(str(testfile))

    # create the file with the same name again -> crashes without the hardlik workarround
    testfile.write('another file')

    assert file_obj.read() == b'hello123'


@pytest.mark.parametrize('file_mode', ['r', 'w', 'a'])
def test_read_while_write(tmpdir, file_mode):
    """Test if a file can be deleted and recreated while it is opened by crosscloud."""
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # create the testfile and leave it open (on windows this is an exlusive open)
    testfile = tmpdir.join('testfile')
    testfile.write('test')

    _ = testfile.open(file_mode)
    mtime = testfile.stat().mtime_ns

    filesystem = Filesystem(str(tmpdir), Mock(), FILESYSTEM_ID)

    # try to open it, should fail (is ok on windows)
    with pytest.raises(CurrentlyNotPossibleError):
        filesystem.open_read(['testfile'])

    # check that the open operation does not modify the mtime
    assert mtime == testfile.stat().mtime_ns

    # now make sure the tmpdir is empty
    assert not tmpdir.join(WriteToTempDirMixin.TEMPDIR).listdir()


@pytest.fixture
def filesystem_non_existing_root(tmpdir):
    """Create Filesystem Storage with non-existing root-dir.

    It needs to be deleted after the instance has been created,
    since the FileSystem class on windows does some checks in the __init__.
    """
    root = tmpdir.join('blabla').mkdir()
    filesystem = Filesystem(str(root), None, FILESYSTEM_ID)
    shutil.rmtree(str(root))
    return filesystem


def test_ne_make_dir(filesystem_non_existing_root):
    """Check if make_dir on non-existing dir raises InvalidOperationError"""
    with pytest.raises(InvalidOperationError):
        filesystem_non_existing_root.make_dir(['hi dir'])


def test_ne_write(filesystem_non_existing_root):
    """Check if write on non-existing dir raises InvalidOperationError"""
    with pytest.raises(InvalidOperationError):
        test_file = io.BytesIO(b'hello')
        filesystem_non_existing_root.write(['hi dir'], test_file)


@pytest.fixture
def tempdir(request):
    """Create a temporary directory and delete it once the test has finished"""
    tempdir = tempfile.mkdtemp()
    request.addfinalizer(lambda: shutil.rmtree(tempdir, ignore_errors=True))
    return tempdir


@pytest.mark.skipif(os.name != 'nt', reason='windows only test')
def test_win_file_read(tempdir):
    """Read a file using WindowsFileReader"""
    fname = 'abc'
    filename = os.path.join(tempdir, fname)

    with open(filename, 'wb') as f_out:
        f_out.write(TEST_STRING)

    f_in = WindowsFileReader(fname=filename, tmpdir=tempdir)
    assert f_in.read(chunk_size=17) == TEST_STRING


@pytest.mark.skipif(os.name != 'nt', reason='windows only test')
def test_win_file_delete_while_read(tempdir):
    """Start reading a file, delete it, continue reading"""
    fname = 'abc'
    filename = os.path.join(tempdir, fname)

    with open(filename, 'wb') as f_out:
        f_out.write(TEST_STRING)

    f_in = WindowsFileReader(fname=filename, tmpdir=tempdir)
    assert bytes(f_in.read(12)) == TEST_STRING[0:12]

    os.unlink(filename)

    assert bytes(f_in.read(12)) == TEST_STRING[12:24]

    f_in.close()
