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
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.OS.OSClass import OSClass
from nmap_scan.Validator import validate

T = TypeVar('T', bound='OSMatch')


class OSMatch:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__os_classes: List[OSClass] = []
        self.__name: Union[str, None] = None
        self.__accuracy: Union[float, None] = None
        self.__line: Union[int, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "name", self.__name
        yield "accuracy", self.__accuracy
        yield "line", self.__line
        yield "osclass", [dict(e) for e in self.__os_classes]

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('osmatch')
        if None is not d.get('accuracy', None):
            xml.attrib['accuracy'] = str(d.get('accuracy', None))
        if None is not d.get('name', None):
            xml.attrib['name'] = d.get('name', None)
        if None is not d.get('line', None):
            xml.attrib['line'] = str(d.get('line', None))

        if None is not d.get('osclass', None):
            for osclass_dict in d['osclass']:
                xml.append(OSClass.dict_to_xml(osclass_dict, validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return OSMatch(OSMatch.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, OSMatch) \
            and self.__name == other.get_name() \
            and self.__accuracy == other.get_accuracy() \
            and self.__line == other.get_line() \
            and compare_lists_equal(self.__os_classes, other.get_os_classes())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_os_classes(self) -> List[OSClass]:
        return self.__os_classes

    def get_name(self) -> str:
        return self.__name

    def get_line(self) -> int:
        return self.__line

    def get_accuracy(self) -> float:
        return self.__accuracy

    def __parse_xml(self):
        logging.info('Parsing OSMatch')

        attr = self.__xml.attrib
        self.__name = attr['name']
        self.__line = int(attr['line'])
        self.__accuracy = int(attr['accuracy'])

        logging.debug('Name: "{name}"'.format(name=self.__name))
        logging.debug('Accuracy: "{accuracy}"'.format(accuracy=self.__accuracy))
        logging.debug('Line: "{line}"'.format(line=self.__line))

        for xml in self.__xml.findall('osclass'):
            self.__os_classes.append(OSClass(xml, False))
