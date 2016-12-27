#!/usr/bin/env python

from pip.req import parse_requirements
from setuptools import find_packages, setup

install_reqs = parse_requirements('requirements.txt', session=False)
reqs = [str(ir.req) for ir in install_reqs]

setup(name="python-kemptech-api",
      version="0.7.14",
      packages=find_packages(),
      author="KEMP Technologies",
      author_email="smcgough@kemptechnologies.com",
      maintainer="Shane McGough",
      maintainer_email="smcgough@kemptechnologies.com,aconti@kemptechnologis.com,spower@kemptechnologies.com",
      description="KEMP Technologies Python API",
      long_description=open('README.md').read(),
      license="Apache",
      keywords="python api kemptech kemp technologies restfull loadmaster",
      url="http://pypi.python.org/pypi/python-kemptech-api/",
      classifiers=[
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Topic :: Internet',
      ],
      include_package_data=True,
      install_requires=reqs
)
