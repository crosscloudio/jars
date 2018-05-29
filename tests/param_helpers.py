"""This module contains functions which makes it easier to paramatize pytest tests."""

import os
import yaml


def read_conf(conf_file_name: str, test_file: str):
    """Return a function which gets the various configurations.

    :conf_file_name: name of the configuration yaml file
    :test_file: __name__ in the file from which read_conf is called.
    :param conf_name: name of the configuration in the yaml file
    """
    test_path = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(test_file)))

    with open(os.path.join(test_path, conf_file_name)) as conf_file:
        conf = yaml.load(conf_file)
        for method, tests in conf.items():
            for test_input in tests:
                yield (method,
                       test_input['expected'],
                       test_input.get('args', []),
                       test_input.get('kwargs', {}))
