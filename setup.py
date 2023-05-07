
from setuptools import setup, find_packages
from scapy_endpoint.core.version import get_version

VERSION = get_version()

f = open('README.md', 'r')
LONG_DESCRIPTION = f.read()
f.close()

setup(
    name='scapy_endpoint',
    version=VERSION,
    description='Endpoint for all scapy network scripts.',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Joe Mama',
    author_email='john.doe@example.com',
    url='https://github.com/johndoe/myapp/',
    license='unlicensed',
    packages=find_packages(exclude=['ez_setup', 'tests*']),
    package_data={'scapy_endpoint': ['templates/*']},
    include_package_data=True,
    entry_points="""
        [console_scripts]
        scapy_endpoint = scapy_endpoint.main:main
    """,
)
