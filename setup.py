# pylint: skip-file
import os
import sys
from setuptools import setup, find_packages
version = "1.3.12"


setup(name='jars',
      version=version,
      description='file storages of every shape and flavour.',
      url='https://gitlab.crosscloud.me/CrossCloud/jars',
      author='CrossCloud GmbH',
      author_email='code+jars@crosscloud.me',
      packages=find_packages(exclude=['tests']),
     zip_safe=False)
