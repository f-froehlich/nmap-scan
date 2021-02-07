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

from lxml import etree

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Data.Element import Element
from nmap_scan.Data.Table import Table
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate


class Script:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__id = None
        self.__output = None
        self.__tables = []
        self.__elements = []
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "id", self.__id
        yield "output", self.__output
        if 0 != len(self.__tables):
            yield "tables", [dict(t) for t in self.__tables]
        if 0 != len(self.__elements):
            yield "elements", [dict(e) for e in self.__elements]

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('script')
        if None != d.get('id', None):
            xml.attrib['id'] = d.get('id', None)
        if None != d.get('output', None):
            xml.attrib['output'] = d.get('output', None)

        if None != d.get('tables', None):
            for table_dict in d['tables']:
                xml.append(Table.dict_to_xml(table_dict, validate_xml))
        if None != d.get('elements', None):
            for element_dict in d['elements']:
                xml.append(Element.dict_to_xml(element_dict, validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            from nmap_scan.Scripts.ScriptParser import parse

            return parse(Script.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, Script) \
               and self.__id == other.get_id() \
               and self.__output == other.get_output() \
               and compare_lists_equal(self.__tables, other.get_tables()) \
               and compare_lists_equal(self.__elements, other.get_elements())

    def get_xml(self):
        return self.__xml

    def get_elements(self):
        return self.__elements

    def get_tables(self):
        return self.__tables

    def get_id(self):
        return self.__id

    def get_output(self):
        return self.__output

    def __parse_xml(self):
        logging.info('Parsing Script')
        attr = self.__xml.attrib
        self.__id = attr['id']
        self.__output = attr.get('output', None)

        for xml in self.get_xml():
            if 'table' == xml.tag:
                self.__tables.append(Table(xml))
            elif 'elem' == xml.tag:
                self.__elements.append(Element(xml))

        logging.debug('ID: "{name}"'.format(name=self.__id))
        logging.debug('Output: "{output}"'.format(output=self.__output))
