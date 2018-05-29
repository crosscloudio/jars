"""
This modules tests windows specificas
"""
import os

import pytest

if os.name == 'nt':
    import jars.fs.windows

# pylint: disable=invalid-name
pytestmark = pytest.mark.skipif(os.name != 'nt', reason="Only for Windows NT")


def test_convert_long_path():
    """ I assume windows is installed on c: and resolve program files or program files
    (x86)"""
    new_path = jars.fs.windows.convert_long_path(r'c:\progra~1')

    assert \
        new_path.casefold() == r'c:\program files' or \
        new_path.casefold() == r'c:\program files (x86)'


# def test_convert_long_path_with_tilde(tmpdir):
#     """ test if files with tilde are ok """
#     p = tmpdir.join('test.~tmp')
#     p.write('Hello')
#     assert jars.fs.windows.convert_long_path(str(p)) == str(p)


def test_convert_long_path_non_exiting():
    """ this if the function throws for a not existing path """
    with pytest.raises(FileNotFoundError):
        jars.fs.windows.convert_long_path('~tmp123123.asd')
