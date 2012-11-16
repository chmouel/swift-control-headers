# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@chmouel.com>"
name = 'swift_control_headers'
entry_point = '%s.middleware:filter_factory' % (name)
version = '0.1'

from setuptools import setup, find_packages

setup(
    name=name,
    version=version,
    description='Swift middleware to deny certain headers.',
    license='Apache License (2.0)',
    author='OpenStack, LLC.',
    author_email='chmouel@chmouel.com',
    url='https://github.com/chmouel/%s' % (name),
    packages=find_packages(),
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
        ],
    install_requires=[],  # removed for better compat
    entry_points={
        'paste.filter_factory': [
            'control_headers=%s' % entry_point,
            ],
        },
    )
