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
from typing import TypeVar, Dict, Union, List
from xml.etree.ElementTree import Element as XMLElement

from lxml import etree

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Data.Element import Element
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate

T = TypeVar('T', bound='Table')


class Table:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__key = None
        self.__tables: List[T] = []
        self.__elements: List[Element] = []
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        if None is not self.__key:
            yield "key", self.__key
        if 0 != len(self.__tables):
            yield "tables", [dict(t) for t in self.__tables]
        if 0 != len(self.__elements):
            yield "elements", [dict(e) for e in self.__elements]

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('table')
        if None is not d.get('key', None):
            xml.attrib['key'] = d.get('key', None)
        if None is not d.get('tables', None):
            for table_dict in d['tables']:
                xml.append(Table.dict_to_xml(table_dict, validate_xml))
        if None is not d.get('elements', None):
            for element_dict in d['elements']:
                xml.append(Element.dict_to_xml(element_dict, validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Table(Table.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, Table) \
            and self.__key == other.get_key() \
            and compare_lists_equal(self.__tables, other.get_tables()) \
            and compare_lists_equal(self.__elements, other.get_elements())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_elements(self) -> List[Element]:
        return self.__elements

    def get_tables(self) -> List[T]:
        return self.__tables

    def get_key(self) -> Union[str, None]:
        return self.__key

    def __parse_xml(self):

        logging.info('Parsing Table')
        attr = self.__xml.attrib
        self.__key = attr.get('key', None)
        logging.debug('Key: "{key}"'.format(key=self.__key))

        for table_xml in self.__xml.findall('table'):
            self.__tables.append(Table(table_xml, False))

        for element_xml in self.__xml.findall('elem'):
            self.__elements.append(Element(element_xml, False))
