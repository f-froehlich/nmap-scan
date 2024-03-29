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
from typing import TypeVar, Dict, Union
from xml.etree.ElementTree import Element as XMLElement

from lxml import etree

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate

T = TypeVar('T', bound='TCPSequence')


class TCPSequence:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__index: Union[int, None] = None
        self.__difficulty: Union[str, None] = None
        self.__values: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "index", self.__index
        yield "difficulty", self.__difficulty
        yield "values", self.__values

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('tcpsequence')
        if None is not d.get('index', None):
            xml.attrib['index'] = str(d.get('index', None))
        if None is not d.get('values', None):
            xml.attrib['values'] = d.get('values', None)
        if None is not d.get('difficulty', None):
            xml.attrib['difficulty'] = d.get('difficulty', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return TCPSequence(TCPSequence.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, TCPSequence) \
            and self.__index == other.get_index() \
            and self.__difficulty == other.get_difficulty() \
            and self.__values == other.get_values()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_index(self) -> int:
        return self.__index

    def get_difficulty(self) -> str:
        return self.__difficulty

    def get_values(self) -> str:
        return self.__values

    def __parse_xml(self):
        logging.info('Parsing TCPSequence')
        attr = self.__xml.attrib
        self.__index = int(attr['index'])
        self.__difficulty = attr['difficulty']
        self.__values = attr['values']

        logging.debug('Index: "{index}"'.format(index=self.__index))
        logging.debug('Difficulty: "{difficulty}"'.format(difficulty=self.__difficulty))
        logging.debug('Values: "{values}"'.format(values=self.__values))
