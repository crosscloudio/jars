"""Classes to handle office 365 storage."""
import logging
import bushn
import jars
from . import OneDriveBusiness
from .microsoft_graph import Office365Api

logger = logging.getLogger(__name__)


class GroupNotFoundException(Exception):
    """Exception raised if a group is not found in the model."""

    pass


class SingleOffice365Group(OneDriveBusiness):
    """Subclass of OneDriveBusiness which is used as substorages for Office365Groups"""
    is_shared = True

    def create_public_sharing_link(self, path):
        """Has not yet been implemented for odb."""
        raise NotImplementedError

    def create_open_in_web_link(self, path):
        """Has not yet been implemented for odb."""
        raise NotImplementedError


def catch_group_not_found_exception(fun):
    """Trap GroupNotFoundException and return None."""
    def new_fun(*args, **kwargs):
        """Return None if the group is not found."""
        try:
            return fun(*args, **kwargs)
        except GroupNotFoundException:
            logger.info('group_not_found: %s, %s, %s', fun.__name__, args, kwargs)
            return

    return new_fun


class Office365Groups(OneDriveBusiness):
    """Office 365 groups allowes groups within an organisation to share data.

    The various groups are modified OneDriveBusiness implementations.
    This storage first collects all avaliable groups and makes them avaliable as sub
    storages.
    """
    API_CLASS = Office365Api

    storage_name = "office365groups"
    storage_display_name = 'Office 365 Groups'
    supports_serialization = True

    def __init__(self, *args, **kwargs):
        """Set the instance attribute group_instances and invoke super's __init__."""
        self.group_instances = {}
        super().__init__(*args, **kwargs)

    def create_new_model(self, name=None):
        """Create a new root node and return it.

        Calls the api and sets the props accordingly.
        """
        model = bushn.IndexingNode(name=None, indexes=['_id'])

        for group_info in self.list_avaliable_groups():
            instance = self._get_sub_storage_by_group_meta(group_meta=group_info)
            instance.model.parent = model

        model.props['metrics'] = jars.StorageMetrics(
            self.storage_id,
            free_space=0,
            total_space=0)
        return model

    def _get_sub_storage_by_group_meta(self, group_meta):
        group_id = group_meta['id']
        if group_id in self.group_instances:
            instance = self.group_instances[group_id]
        else:
            instance = SingleOffice365Group(api=self.api,
                                            event_sink=self._event_sink,
                                            storage_id=self.storage_id,
                                            group_id=group_id)

            name = group_meta['displayName']
            try:
                node = instance.create_new_model(name=name)
            except FileNotFoundError:
                # the server returned a 404, this happens when a group has been added,
                # but microsoft still needs time to get the api setup
                raise GroupNotFoundException
            node.props[jars.VERSION_ID] = jars.FOLDER_VERSION_ID
            node.props[jars.IS_DIR] = True
            node.props['_group_id'] = group_id
            node.props[jars.SHARED] = True
            node.props[jars.SHARE_ID] = group_id
            node.props['_owners'] = group_meta['owners']
            instance.model = node

        self.group_instances[group_id] = instance
        return instance

    def get_update(self, model=None, emit_events=False):
        """Return an updated version of the provided model.

        If model is set to None, a brand new model is created.

        :param model: model to update. defaults to None
        :param emit_events: wether to trigger events when merging.
        """
        for group in self.list_avaliable_groups():
            try:
                instance = self._get_sub_storage_by_group_meta(group)
                instance.get_update(model=instance.model, emit_events=emit_events)
            except GroupNotFoundException as exception:
                logger.exception(exception)
                continue
        return model

    def _get_sub_storage(self, path):
        try:
            node = self.model.get_node(path[:1])
            group_id = node.props['_group_id']
            return self.group_instances[group_id]
        except KeyError:
            all_groups = self.list_avaliable_groups()
            # TODO: add normalization instead of just lower
            group = [group for group in all_groups
                     if group['displayName'].lower() == path[0]]
            if len(group) == 0:
                raise GroupNotFoundException
            else:
                return self._get_sub_storage_by_group_meta(group[0])

    @catch_group_not_found_exception
    def make_dir(self, path):
        """Create a directory on the storage, implicitly creating all parents."""
        if len(path) == 1:
            return jars.FOLDER_VERSION_ID

        return self._get_sub_storage(path).make_dir(path[1:])

    # @catch_group_not_found_exception
    def get_tree_children(self, path):
        """Return the children of the provided path as """

        if path == [] or path == [None]:
            for group in self.list_avaliable_groups():
                props = {jars.VERSION_ID: jars.FOLDER_VERSION_ID,
                         jars.IS_DIR: True,
                         jars.SHARED: True,
                         '_group_id': group['id'],
                         jars.SHARE_ID: group['id'],
                         '_owners': group['owners']}
                yield (group['displayName'], props)
        else:
            return self._get_sub_storage(path).get_tree_children(path[1:])

    @catch_group_not_found_exception
    def move(self, source, target, expected_source_vid=None, expected_target_vid=None):
        """Move an item from source to target."""
        if source[0] == target[0]:
            # the item is in the same group, and the substroages move can be invoked.
            sub_storage = self._get_sub_storage(source)
            return sub_storage.move(source=source[1:],
                                    target=target[1:],
                                    expected_source_vid=expected_source_vid,
                                    expected_target_vid=expected_target_vid)
        else:
            # items are not in the same group, the item must be read from one group and
            # written to another.
            source_sub_storage = self._get_sub_storage(source)
            target_sub_storage = self._get_sub_storage(source)
            f_in = source_sub_storage.open_read(path=source[1:],
                                                expected_version_id=expected_source_vid)
            target_sub_storage.write(path=target[1:],
                                     file_obj=f_in,
                                     original_version_id=expected_target_vid)

            # and then it can be deleted from the source group.
            source_sub_storage.delete(path=source[1:],
                                      original_version_id=expected_source_vid)

    @catch_group_not_found_exception
    def open_read(self, path, expected_version_id=None):
        """Return the open_read of the sub_storage"""
        sub_storage = self._get_sub_storage(path)
        return sub_storage.open_read(path=path[1:],
                                     expected_version_id=expected_version_id)

    @catch_group_not_found_exception
    def delete(self, path, original_version_id=None):
        """Delete from the substorage"""
        sub_storage = self._get_sub_storage(path)
        if len(path) == 1:
            # group folder has been deleted so disable it in selective sync
            # by removing from the filter_tree
            self.filter_tree.get_node(path).delete()

            # and remove the instance from group_instances.
            del self.group_instances[sub_storage.group_id]
        else:
            return sub_storage.delete(path[1:], original_version_id)

    @catch_group_not_found_exception
    def write(self, path, file_obj, original_version_id=None, size=None):
        sub_storage = self._get_sub_storage(path)
        return sub_storage.write(path=path[1:],
                                 file_obj=file_obj,
                                 original_version_id=original_version_id,
                                 size=size)

    def get_shared_folders(self):
        shared_folders = []
        for child, props in self.get_tree_children(path=[]):
            path = [child]
            try:
                instance = self._get_sub_storage(path)
            except GroupNotFoundException:
                logger.info('Group %s can not yet be accessed', child)
                continue
            shared_folders.append(jars.SharedFolder(path=path,
                                                    share_id=instance.group_id,
                                                    sp_user_ids=set(props['_owners'])))
        # logger.info('### self.api.drive_id: %s', self.api.drive_id)
        # logger.info('+++ shared_folders: %s', shared_folders)

        return shared_folders

    def create_public_sharing_link(self, path):
        """Has not yet been implemented for office365."""
        raise NotImplementedError

    def create_open_in_web_link(self, path):
        """Has not yet been implemented for office365."""
        raise NotImplementedError
