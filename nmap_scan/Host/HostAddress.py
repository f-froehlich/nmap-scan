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

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union

T = TypeVar('T', bound='HostAddress')


class HostAddress:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__addr: Union[str, None] = None
        self.__vendor: Union[str, None] = None
        self.__type: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "addr", self.__addr
        if None is not self.__vendor:
            yield "vendor", self.__vendor
        yield "type", self.__type

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('address')

        if None is not d.get('addr', None):
            xml.attrib['addr'] = d.get('addr', None)
        if None is not d.get('vendor', None):
            xml.attrib['vendor'] = d.get('vendor', None)
        if None is not d.get('type', None):
            xml.attrib['addrtype'] = d.get('type', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return HostAddress(HostAddress.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, HostAddress) \
            and self.__addr == other.get_addr() \
            and self.__vendor == other.get_vendor() \
            and self.__type == other.get_type()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_addr(self) -> str:
        return self.__addr

    def get_type(self) -> str:
        return self.__type

    def get_vendor(self) -> Union[str, None]:
        return self.__vendor

    def is_ipv4(self) -> bool:
        return 'ipv4' == self.__type

    def is_ipv6(self) -> bool:
        return 'ipv6' == self.__type

    def is_ip(self):
        return self.is_ipv4() or self.is_ipv6()

    def is_mac(self) -> bool:
        return 'mac' == self.__type

    def __parse_xml(self):
        logging.info('Parsing HostAddress')
        attr = self.__xml.attrib
        self.__addr = attr['addr']
        self.__type = attr.get('addrtype', 'ipv4')
        self.__vendor = attr.get('vendor', None)
        logging.debug('Address: "{addr}"'.format(addr=self.__addr))
        logging.debug('Type: "{type}"'.format(type=self.__type))
        logging.debug('Vendor: "{vendor}"'.format(vendor=self.__vendor))
