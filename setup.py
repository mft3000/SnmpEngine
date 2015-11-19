from setuptools import setup, find_packages
from pip.req import parse_requirements
import uuid

# parse_requirements() returns generator of pip.req.InstallRequirement objects
install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())

# reqs is a list of requirement
# e.g. ['django==1.5.1', 'mezzanine==1.4.6']
reqs = [str(ir.req) for ir in install_reqs]

version = '3.0'

setup(
    name='snmpEngine',
    version=version,
    py_modules=['snmpEngine'],
    packages=find_packages(),
    install_requires=reqs,
    include_package_data=True,
    description = 'Python Lib to interact with network devices using snmp',
    author = 'Francesco Marangione',
    author_email = 'fmarangi@cisco.com',
    url = 'https://github.com/mft3000/snmpEngine', # use the URL to the github repo
    download_url = 'https://github.com/mft3000/snmpEngine/tarball/%s' % version,
    keywords = ['snmp', 'Cisco', 'networking'],
    classifiers = [],
)
