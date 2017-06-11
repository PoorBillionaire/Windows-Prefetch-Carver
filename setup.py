from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='prefetchcarve',
    version='1.1.2',
    description='A Python script to carve Windows Prefetch artifacts from arbitrary binary data',
    long_description=long_description,
    url='https://github.com/PoorBillionaire/Windows-Prefetch-Carver',
    author='Adam Witt',
    author_email='accidentalassist@gmail.com',
    license='Apache Software License',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: Apache Software License'
    ],

    packages=find_packages(),
    scripts=['prefetch-carve.py']
)
