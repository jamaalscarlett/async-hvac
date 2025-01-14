#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='async-hvac',
    version='0.7.0',
    description='HashiCorp Vault API client',
    long_description='HashiCorp Vault API python 3.6+ client using asyncio.',
    author='Lionel Zerbib',
    author_email='lionel@alooma.io',
    url='https://github.com/Aloomaio/async-hvac',
    keywords=['hashicorp', 'vault', 'hvac'],
    classifiers=['License :: OSI Approved :: Apache Software License'],
    packages=find_packages(),
    install_requires=[
        'aiohttp>=3.3.1',
    ],
    include_package_data=True,
    extras_require={
        'parser': ['pyhcl>=0.4.5']
    }
)
