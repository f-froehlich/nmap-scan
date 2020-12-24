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


class HostName:

    def __init__(self, xml):
        self.__xml = xml
        self.__name = None
        self.__type = None
        self.__parse_xml()

    def equals(self, other):
        return isinstance(other, HostName) \
               and self.__name == other.get_name() \
               and self.__type == other.get_type()

    def get_xml(self):
        return self.__xml

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def __parse_xml(self):
        logging.info('Parsing HostName')
        attr = self.__xml.attrib
        self.__name = attr.get('name', None)
        self.__type = attr.get('type', None)
        logging.debug('Name: "{name}"'.format(name=self.__name))
        logging.debug('Type: "{type}"'.format(type=self.__type))
