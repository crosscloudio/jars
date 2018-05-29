"""Test what happens when storage class is initialized."""


def test_tree_loaded(mocker, storage_test_setup):
    """When initializing the storage don't overwrite the tree returned by load_model.

    If this test fails the storage must fetch the full tree on each restart. The tree we
    save to disk is effectively useless.
    """

    # Set a tree
    tree = storage_test_setup.NODE_CLASS(**storage_test_setup.ROOT_INIT_PARAMS)

    # Return that tree when load module is called in the base.__init__()
    with mocker.patch('jars.load_model', return_value=tree):
        storage = storage_test_setup.STORAGE_CLASS(**storage_test_setup.init_params)

    # Ensure that the tree is still the unique value after init has been run.
    assert storage.tree is tree, 'tree is not loaded from cache'

    # Ensure no children have been added
    assert len(storage.tree.children) == 0, 'Children added during storage.__init__'

    # And the props should be empty
    assert storage.tree.props == {}, 'props are added during storage.__init__'
