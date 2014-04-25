#!/usr/bin/env python

import os
from setuptools import setup, find_packages
from multiprocessing import util

setup(name='RadiusServer',
      version='1.0',
      description='Python Radius Server',
      author='Craig I. Hagan',
      author_email='hagan@cih.com',
      url='n/a',
      #packages=['awssecrets','radiusauthenticator','radiusencryption','radiusmessage','radiususermapper','radiusconstants','radiushealthcheck','radiussecrets'],
      packages = find_packages(exclude=["test"]),
      test_suite="test",
)
