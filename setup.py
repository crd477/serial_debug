#!/usr/bin/python2.7

from setuptools import setup, find_packages

setup(name='serial_debug',
	version='0.1',
	description='A tool for adding serial port debugging to openstack instances',
	author='David Bryson',
	author_email='david@statichacks.org',
	packages=find_packages(),
	entry_points = {'nova.hooks': ["run_instance=serial_debug.hooks:serial_debug_run_hook",
                                       "delete_instance=serial_debug.hooks:serial_debug_teardown",]}
)
