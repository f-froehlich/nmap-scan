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

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Host.HostName import HostName
from nmap_scan.Stats.Status import Status


class HostHint:

    def __init__(self, xml):
        self.__xml = xml
        self.__statuses = []
        self.__addresses = []
        self.__hostnames = []
        self.__parse_xml()

    def equals(self, other):
        return isinstance(other, HostHint) \
               and compare_lists_equal(self.__statuses, other.get_statuses()) \
               and compare_lists_equal(self.__addresses, other.get_addresses()) \
               and compare_lists_equal(self.__hostnames, other.get_hostnames())

    def get_xml(self):
        return self.__xml

    def get_statuses(self):
        return self.__statuses

    def get_addresses(self):
        return self.__addresses

    def get_hostnames(self):
        return self.__hostnames

    def __parse_xml(self):
        logging.info('Parsing HostHint')

        for xml in self.__xml.findall('status'):
            self.__statuses.append(Status(xml))

        for xml in self.__xml.findall('address'):
            self.__addresses.append(HostAddress(xml))

        hostnames_xml = self.__xml.find('hostnames')
        if hostnames_xml != None:
            for hostname_xml in hostnames_xml.findall('hostname'):
                self.__hostnames.append(HostName(hostname_xml))
