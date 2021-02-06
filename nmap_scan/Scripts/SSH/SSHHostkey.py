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
from nmap_scan.Scripts.Script import Script
from nmap_scan.Validator import validate


class SSHHostkey(Script):

    def __init__(self, xml):
        self.__xml = xml
        Script.__init__(self, xml)
        self.__keys = []
        self.__parse_xml()

    def equals(self, other):
        return isinstance(other, SSHHostkey) \
               and Script.equals(self, other) \
               and compare_lists_equal(self.__keys, other.get_keys())

    def get_xml(self):
        return self.__xml

    def get_keys(self):
        return self.__keys

    def __parse_xml(self):
        logging.info('Parsing SSHHostkey')

        xml_tables = self.__xml.findall('table')
        for xml_table in xml_tables:
            self.__keys.append(Key(xml_table))


class Key:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__bits = None
        self.__key = None
        self.__type = None
        self.__fingerprint = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def equals(self, other):
        return isinstance(other, Key) \
               and self.__bits == other.get_bits() \
               and self.__key == other.get_key() \
               and self.__type == other.get_type() \
               and self.__fingerprint == other.get_fingerprint()

    def get_xml(self):
        return self.__xml

    def get_bits(self):
        return self.__bits

    def get_key(self):
        return self.__key

    def get_fingerprint(self):
        return self.__fingerprint

    def get_type(self):
        return self.__type

    def __parse_xml(self):
        logging.info('Parsing Key')

        for element in self.__xml.findall('elem'):
            key = element.attrib.get('key', 'unknown')
            if 'key' == key:
                self.__key = element.text
            elif 'bits' == key:
                self.__bits = int(element.text)
            elif 'type' == key:
                self.__type = element.text
            elif 'fingerprint' == key:
                self.__fingerprint = element.text
