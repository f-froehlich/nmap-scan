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


import os
from distutils import log

from setuptools import setup, find_packages
from setuptools.command.install import install


class OverrideInstall(install):
    def run(self):
        mode = 0o755
        install.run(self)

        # here we start with doing our overriding and private magic ..
        log.info("Overriding setuptools mode of scripts ...")
        for filepath in self.get_outputs():
            log.info("Changing permissions of %s to %s" % (filepath, oct(mode)))
            os.chmod(filepath, mode)


with open('README.md') as readme_file:
    README = readme_file.read()
with open('CHANGELOG.md') as changelog_file:
    CHANGELOG = changelog_file.read()

additional_files = [
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
]
setup_args = dict(
    name='nmap_scan',
    version='0.0.1',
    description='Nmap wrapper for python',
    long_description_content_type="text/markdown",
    long_description=README + '\n\n\n' + CHANGELOG,
    license='AGPLv3',
    packages=find_packages(),
    author='Fabian Fröhlich',
    author_email='mail@confgen.org',
    keywords=['nmap', 'serverstatus', ],
    url='https://github.com/f-froehlich/monitoring-scripts',
    download_url='https://pypi.org/project/monitoring-scripts/',
    package_data={'monitoring_scripts': ['*.sh']},
    data_files=[('monitoring_scripts_doc', additional_files)]
)

install_requires = [
]

if __name__ == '__main__':
    setup(**setup_args, install_requires=install_requires, cmdclass={'install': OverrideInstall})
