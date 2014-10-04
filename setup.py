from setuptools import setup, find_packages
from codecs import open

setup(
    name='sm-openid',
    version='0.1.dev1',
    description='OpenID consumer. Supports versions 1 and 2 of the OpenID protocol.',
    long_description=open('README.md', encoding='utf-8').read(),
    url='https://github.com/isagalaev/sm-openid',
    author='Ivan Sagalaev',
    author_email='maniac@softwaremaniacs.org',
    license='Apache',
    keywords='openid consumer',

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],

    install_requires=['html5lib'],
    packages=find_packages(exclude=['examples', 'openid.test']),
)
