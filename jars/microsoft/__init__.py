"""Ths module combines the various storages provided by microsoft.
"""

from .onedrive import OneDrive
from .onedrive_for_business import OneDriveBusiness
from .office365 import Office365Groups
from .sharepoint import SharePoint

import jars
jars.registered_storages.append(OneDrive)
jars.registered_storages.append(OneDriveBusiness)
jars.registered_storages.append(Office365Groups)
jars.registered_storages.append(SharePoint)
