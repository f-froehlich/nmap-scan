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

T = TypeVar('T', bound='ExtraReason')


class ExtraReason:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__reason: Union[str, None] = None
        self.__count: Union[int, None] = None
        self.__proto: Union[str, None] = None
        self.__ports: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "reason", self.__reason
        yield "count", self.__count
        if None is not self.__proto:
            yield "proto", self.__proto
        if None is not self.__ports:
            yield "ports", self.__ports

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('extrareasons')
        if None is not d.get('reason', None):
            xml.attrib['reason'] = d.get('reason', None)
        if None is not d.get('count', None):
            xml.attrib['count'] = d.get('count', None)
        if None is not d.get('proto', None):
            xml.attrib['proto'] = d.get('proto', None)
        if None is not d.get('ports', None):
            xml.attrib['ports'] = d.get('ports', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return ExtraReason(ExtraReason.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, ExtraReason) \
            and self.__reason == other.get_reason() \
            and self.__count == other.get_count() \
            and self.__proto == other.get_proto() \
            and self.__ports == other.get_ports()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_count(self) -> int:
        return self.__count

    def get_reason(self) -> str:
        return self.__reason

    def get_ports(self) -> Union[str, None]:
        return self.__ports

    def get_proto(self) -> Union[str, None]:
        return self.__proto

    def __parse_xml(self):
        logging.info('Parsing ExtraReason')
        attr = self.__xml.attrib
        self.__reason = attr['reason']
        self.__count = attr['count']
        self.__proto = attr.get('proto', None)
        self.__ports = attr.get('ports', None)

        logging.debug('Reason: "{reason}"'.format(reason=self.__reason))
        logging.debug('Count: "{count}"'.format(count=self.__count))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))
        logging.debug('Ports: "{ports}"'.format(ports=self.__ports))
