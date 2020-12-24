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


class ScanInfo:

    def __init__(self, xml):
        self.__xml = xml
        self.__type = None
        self.__protocol = None
        self.__scan_flags = None
        self.__num_services = None
        self.__services = None
        self.__parse_xml()

    def equals(self, other):
        return isinstance(other, ScanInfo) \
               and self.__type == other.get_type() \
               and self.__protocol == other.get_protocol() \
               and self.__scan_flags == other.get_scan_flags() \
               and self.__num_services == other.get_num_services() \
               and self.__services == other.get_services()

    def get_type(self):
        return self.__type

    def get_xml(self):
        return self.__xml

    def get_protocol(self):
        return self.__protocol

    def get_num_services(self):
        return self.__num_services

    def get_services(self):
        return self.__services

    def get_scan_flags(self):
        return self.__scan_flags

    def __parse_xml(self):
        logging.info('Parsing Scaninfo')
        attr = self.__xml.attrib
        self.__type = attr['type']
        self.__protocol = attr['protocol']
        self.__num_services = int(attr['numservices'])
        self.__services = attr['services']
        self.__scan_flags = attr.get('scanflags', None)

        logging.debug('Type: "{value}"'.format(value=self.__type))
        logging.debug('Protocol: "{value}"'.format(value=self.__protocol))
        logging.debug('Number of Services: "{value}"'.format(value=self.__num_services))
        logging.debug('Services: "{value}"'.format(value=self.__services))
        logging.debug('Scan flags: "{scanflags}"'.format(scanflags=self.__scan_flags))
