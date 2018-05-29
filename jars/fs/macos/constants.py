"""import and setup various imports needed for interacting with fsevents

more info at https://developer.apple.com/reference/coreservices/core_services_enumerations/1455361-fseventstreameventflags # noqa
"""
# pylint: skip-file
from _fsevents import (CF_POLLIN, CF_POLLOUT, FS_CFLAGFILEEVENTS,
                       FS_CFLAGIGNORESELF, FS_CFLAGNODEFER, FS_CFLAGNONE,
                       FS_CFLAGUSECFTYPES, FS_CFLAGWATCHROOT,
                       FS_EVENTIDSINCENOW, FS_FILEEVENTS,
                       FS_FLAGEVENTIDSWRAPPED, FS_FLAGHISTORYDONE,
                       FS_FLAGKERNELDROPPED, FS_FLAGMOUNT,
                       FS_FLAGMUSTSCANSUBDIRS, FS_FLAGNONE, FS_FLAGROOTCHANGED,
                       FS_FLAGUNMOUNT, FS_FLAGUSERDROPPED, FS_IGNORESELF,
                       FS_ITEMCHANGEOWNER, FS_ITEMCREATED,
                       FS_ITEMFINDERINFOMOD, FS_ITEMINODEMETAMOD, FS_ITEMISDIR,
                       FS_ITEMISFILE, FS_ITEMISSYMLINK, FS_ITEMMODIFIED,
                       FS_ITEMREMOVED, FS_ITEMRENAMED, FS_ITEMXATTRMOD, loop,
                       schedule, stop, unschedule)


# Using this flag, we can get file level events.
FS_EVENTSTREAM_CREATE_FLAG_FILE_EVENTS = 0x00000010
