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


import logging

from nmap_scan.Exceptions import LogicError
from nmap_scan.Host import Host
from nmap_scan.ScanInfo import ScanInfo


class Report:

    def __init__(self, xml):
        self.__xml = xml
        self.__scanner = None
        self.__scanner_args = None
        self.__start = None
        self.__startstr = None
        self.__version = None
        self.__xmloutputversion = None
        self.__scaninfo = None
        self.__verbose_level = None
        self.__debugging_level = None

        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_scanner(self):
        return self.__scanner

    def get_scannder_args(self):
        return self.__scanner_args

    def get_start(self):
        return self.__start

    def get_start_string(self):
        return self.__startstr

    def get_version(self):
        return self.__version

    def get_xml_output_version(self):
        return self.__xmloutputversion

    def get_scaninfo(self):
        return self.__scaninfo

    def get_verbose_level(self):
        return self.__verbose_level

    def get_debugging_level(self):
        return self.__debugging_level

    def __parse_xml(self):
        nmaprun = self.get_xml().attrib
        self.__scanner = nmaprun['scanner']
        self.__scanner_args = nmaprun['args']
        self.__start = int(nmaprun['start'])
        self.__startstr = nmaprun['startstr']
        self.__version = nmaprun['version']
        self.__xmloutputversion = nmaprun['xmloutputversion']

        self.__verbose_level = int(self.get_xml().find('verbose').attrib['level'])
        self.__debugging_level = int(self.get_xml().find('debugging').attrib['level'])

        self.__scaninfo = ScanInfo(self.get_xml().find('scaninfo'))


class TCPReport(Report):

    def __init__(self, xml):
        Report.__init__(self, xml)
        self.__hosts = []
        self.__parse_xml()

    def get_hosts(self):
        return self.__hosts

    def __parse_xml(self):
        if None == self.get_xml():
            raise LogicError('No valid xml is set.')
        logging.info('Parsing TCP Report')

        for host_xml in self.get_xml().findall('host'):
            self.__hosts.append(Host(host_xml))
