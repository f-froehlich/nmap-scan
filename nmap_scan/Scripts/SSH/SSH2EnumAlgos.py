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

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Scripts.Script import Script


class SSH2EnumAlgos(Script):

    def __init__(self, xml):
        Script.__init__(self, xml)
        self.__xml = xml
        self.__kex_algorithms = []
        self.__server_host_key_algorithms = []
        self.__encryption_algorithms = []
        self.__mac_algorithms = []
        self.__compression_algorithms = []
        self.__other = {}
        self.__parse_xml()

    def equals(self, other):
        status = isinstance(other, SSH2EnumAlgos) \
                 and Script.equals(self, other) \
                 and compare_lists(self.__kex_algorithms, other.get_kex_algorithms()) \
                 and compare_lists(self.__server_host_key_algorithms, other.get_server_host_key_algorithms()) \
                 and compare_lists(self.__encryption_algorithms, other.get_encryption_algorithms()) \
                 and compare_lists(self.__mac_algorithms, other.get_mac_algorithms()) \
                 and compare_lists(self.__compression_algorithms, other.get_compression_algorithms()) \
                 and len(self.__other) == len(other.get_other())

        if status:
            other_elements_other = other.get_other()
            for other_key in self.__other:
                if not compare_lists(self.__other[other_key], other_elements_other.get(other_key, [])):
                    return False

        return status

    def get_xml(self):
        return self.__xml

    def get_kex_algorithms(self):
        return self.__kex_algorithms

    def get_server_host_key_algorithms(self):
        return self.__server_host_key_algorithms

    def get_encryption_algorithms(self):
        return self.__encryption_algorithms

    def get_mac_algorithms(self):
        return self.__mac_algorithms

    def get_compression_algorithms(self):
        return self.__compression_algorithms

    def get_other(self):
        return self.__other

    def __parse_xml(self):

        logging.info('Parsing SSH2EnumAlgos')

        xml_tables = self.__xml.findall('table')
        for xml_table in xml_tables:
            key = xml_table.attrib.get('key', 'unknown')
            logging.debug('Parsing: "{key}"'.format(key=key))

            elements = []
            for xml_element in xml_table.findall('elem'):
                logging.debug('Found: "{element}"'.format(element=xml_element.text))
                elements.append(xml_element.text)

            if 'kex_algorithms' == key:
                self.__kex_algorithms += elements
            elif 'server_host_key_algorithms' == key:
                self.__server_host_key_algorithms += elements

            elif 'encryption_algorithms' == key:
                self.__encryption_algorithms += elements

            elif 'mac_algorithms' == key:
                self.__mac_algorithms += elements

            elif 'compression_algorithms' == key:
                self.__compression_algorithms += elements
            else:
                self.__other[key] = self.__other.get(key, []) + elements
