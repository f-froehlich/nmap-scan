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

from nmap_scan.Data.Element import Element


class Table:

    def __init__(self, xml):
        self.__xml = xml
        self.__key = None
        self.__tables = []
        self.__elements = []
        self.__parse_xml()

    def equals(self, other):
        status = isinstance(other, Table) \
                 and self.__key == other.get_key() \
                 and len(self.__tables) == len(other.get_tables()) \
                 and len(self.__elements) == len(other.get_elements())

        if status:

            for own_element in self.__elements:
                exist = False
                for other_element in other.get_elements():
                    if own_element.equals(other_element):
                        exist = True
                        break

                if not exist:
                    return False

            for other_element in other.get_elements():
                exist = False
                for own_element in self.__elements:
                    if own_element.equals(other_element):
                        exist = True
                        break

                if not exist:
                    return False

            for own_table in self.__tables:
                exist = False
                for other_table in other.get_tables():
                    if own_table.equals(other_table):
                        exist = True
                        break

                if not exist:
                    return False

            for other_table in other.get_tables():
                exist = False
                for own_table in self.__tables:
                    if own_table.equals(other_table):
                        exist = True
                        break

                if not exist:
                    return False

        return status

    def get_xml(self):
        return self.__xml

    def get_elements(self):
        return self.__elements

    def get_tables(self):
        return self.__tables

    def get_key(self):
        return self.__key

    def __parse_xml(self):

        logging.info('Parsing Table')
        attr = self.__xml.attrib
        self.__key = attr.get('key', None)
        logging.debug('Key: "{key}"'.format(key=self.__key))

        for table_xml in self.__xml.findall('table'):
            self.__tables.append(Table(table_xml))

        for element_xml in self.__xml.findall('elem'):
            self.__elements.append(Element(element_xml))
