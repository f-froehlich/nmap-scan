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


class HostAddress:

    def __init__(self, xml):
        self.__xml = xml
        self.__addr = None
        self.__vendor = None
        self.__type = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_addr(self):
        return self.__addr

    def get_type(self):
        return self.__type

    def get_vendor(self):
        return self.__vendor

    def is_ipv4(self):
        return 'ipv4' == self.__type

    def is_ipv6(self):
        return 'ipv6' == self.__type

    def is_ip(self):
        return self.is_ipv4() or self.is_ipv6()

    def is_mac(self):
        return 'mac' == self.__type

    def __parse_xml(self):
        logging.info('Parsing HostAddress')
        attr = self.__xml.attrib
        self.__addr = attr['addr']
        self.__type = attr['addrtype']
        self.__vendor = attr.get('addrtype', None)
        logging.debug('Address: "{addr}"'.format(addr=self.__addr))
        logging.debug('Type: "{type}"'.format(type=self.__type))
        logging.debug('Vendor: "{vendor}"'.format(vendor=self.__vendor))
