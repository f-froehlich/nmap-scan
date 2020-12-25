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

from nmap_scan.CompareHelper import compare_lists_equal
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
        return isinstance(other, UnknownScript) \
               and Script.equals(self, other) \
               and compare_lists_equal(self.__tables, other.get_tables()) \
               and compare_lists_equal(self.__elements, other.get_elements()) \
               and compare_lists(self.__data, other.get_data())

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
