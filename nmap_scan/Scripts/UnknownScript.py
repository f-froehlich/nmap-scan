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

from compare_xml.Comparator import compare_lists

from nmap_scan.Data.Element import Element
from nmap_scan.Data.Table import Table
from nmap_scan.Scripts.Script import Script


class UnknownScript(Script):

    def __init__(self, xml):
        Script.__init__(self, xml)
        self.__tables = []
        self.__elements = []
        self.__data = []
        self.__parse_xml()

    def equals(self, other):
        status = isinstance(other, UnknownScript) \
                 and Script.equals(self, other) \
                 and len(self.__tables) == len(other.get_tables()) \
                 and len(self.__elements) == len(other.get_elements()) \
                 and len(self.__data) == len(other.get_data())

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

            if not compare_lists(self.__data, other.get_data()):
                return False

        return status

    def get_elements(self):
        return self.__elements

    def get_tables(self):
        return self.__tables

    def get_data(self):
        return self.__data

    def __parse_xml(self):

        logging.info('Parsing UnknownScript')

        for xml in self.get_xml():
            if 'table' == xml.tag:
                self.__tables.append(Table(xml))
            elif 'elem' == xml.tag:
                self.__elements.append(Element(xml))
            else:
                self.__data.append(xml)
