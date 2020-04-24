# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup

try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements


base_dir = os.path.dirname(__file__)
install_requires = parse_requirements(os.path.join(base_dir, '../../../requirements.txt'), session=False)
install_requires_list = [str(ir.req) for ir in install_requires]
setup(
    name='elastalert',
    version='0.1.35',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main',
                            'elastalert=elastalert.elastalert:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml']},
    install_requires=install_requires_list
)
