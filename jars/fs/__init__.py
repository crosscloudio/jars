"""
File System Module
"""

import os
import sys

from jars.utils import WriteToTempDirMixin

if os.name == 'nt':
    from .windows import WindowsFileBaseSystem as FilesystemBasic
elif sys.platform == 'darwin':
    from .macos import MacOSFileBaseSystem as FilesystemBasic
else:
    from .filesystem import FilesystemBasic


class Filesystem(WriteToTempDirMixin, FilesystemBasic):
    """
    The basic filesystem with :class:`WriteToTempDirMixin`
    """
    # pylint: disable-all
    pass
