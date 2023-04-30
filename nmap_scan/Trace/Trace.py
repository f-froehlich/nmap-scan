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
from nmap_scan.Trace.Hop import Hop
from nmap_scan.Validator import validate

T = TypeVar('T', bound='Trace')


class Trace:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__hops: List[Hop] = []
        self.__proto: Union[str, None] = None
        self.__port: Union[int, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "hops", [dict(h) for h in self.__hops]
        if None is not self.__proto:
            yield "proto", self.__proto
        if None is not self.__port:
            yield "port", self.__port

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('trace')
        if None is not d.get('port', None):
            xml.attrib['port'] = str(d.get('port', None))
        if None is not d.get('proto', None):
            xml.attrib['proto'] = d.get('proto', None)

        if None is not d.get('hops', None):
            for hop_dict in d['hops']:
                xml.append(Hop.dict_to_xml(hop_dict))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()
        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Trace(Trace.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_hops(self) -> List[Hop]:
        return self.__hops

    def get_proto(self) -> Union[str, None]:
        return self.__proto

    def get_port(self) -> Union[int, None]:
        return self.__port

    def equals(self, other: T) -> bool:
        return isinstance(other, Trace) \
            and self.__proto == other.get_proto() \
            and self.__port == other.get_port() \
            and compare_lists_equal(self.__hops, other.get_hops())

    def __parse_xml(self):
        logging.info('Parsing Trace')
        attr = self.__xml.attrib
        self.__port = int(attr['port']) if None is not attr.get('port', None) else None
        self.__proto = attr.get('proto', None)

        logging.debug('Port: "{port}"'.format(port=self.__port))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))

        for xml in self.__xml.findall('hop'):
            self.__hops.append(Hop(xml, False))
