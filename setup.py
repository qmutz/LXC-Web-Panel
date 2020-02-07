#!/usr/bin/env python
import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
VERSION = open(os.path.join(here, 'gantry/version')).read()

setup(
    name='pantry',
    version=VERSION,
    description='Pantry LXC Web Panel',
    long_description=README,
    author='EstudioNexos, Claudio Mignanti',
    author_email='hola@estudionexos.com, c.mignanti@gmail.com',
    url='https://github.com/EstudioNexos/LXC-Web-Panel',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    scripts=['bin/ptr'],
)
