#!/usr/bin/python3
# -*- coding: utf-8

#  nmap-scan
#
#  Nmap wrapper for python
#
#  Copyright (c) 2020 Fabian Fröhlich <mail@nmap-scan.de> <https://nmap-scan.de>
#
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#  For all license terms see README.md and LICENSE Files in root directory of this Project.
#
#  Checkout this project on github <https://github.com/f-froehlich/nmap-scan>
#  and also my other projects <https://github.com/f-froehlich>


from setuptools import setup, find_packages

with open('README.md') as readme_file:
    README = readme_file.read()
with open('CHANGELOG.md') as changelog_file:
    CHANGELOG = changelog_file.read()
with open('CONTRIBUTORS.md') as changelog_file:
    CONTRIBUTORS = changelog_file.read()
with open('LICENSE') as changelog_file:
    LICENSE = changelog_file.read()

additional_files = [
    'README.md',
    'CHANGELOG.md',
    'CONTRIBUTORS.md',
    'LICENSE',
    'nmap.dtd',
    'nmap.xsl',
]
setup_args = dict(
    name='nmap_scan',
    version='1.0.0',
    description='Nmap wrapper for python with complete Nmap DTD support',
    long_description_content_type="text/markdown",
    long_description=README + '\n\n\n' + CONTRIBUTORS + '\n\n\n' + CHANGELOG,
    license='AGPLv3',
    packages=find_packages(),
    author='Fabian Fröhlich',
    author_email='mail@confgen.org',
    maintainer='Fabian Fröhlich',
    maintainer_email='mail@confgen.org',
    keywords=['nmap', 'serverstatus', 'security', 'secutity-tools', 'scanner', 'scanning', 'portscanner',
              'portscanning', 'network-scanner', 'os-identifier', 'service-discovery', 'service-detection', ],
    download_url='https://github.com/f-froehlich/nmap-scan',
    url='https://nmap-scan.de',
    package_data={'nmap_scan': additional_files},
)

install_requires = [
    'compare-xml>=1.1',
    'lxml>=4.5',
    'requests>=2.22',
    'xmltodict>=0.12'
    # 'pytest',
    # 'pytest-cov',
    # 'pytest-snapshot',
]

if __name__ == '__main__':
    setup(**setup_args, install_requires=install_requires)
