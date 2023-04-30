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

T = TypeVar('T', bound='Hop')


class Hop:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__ttl: Union[int, None] = None
        self.__rtt: Union[int, None] = None
        self.__ip: Union[str, None] = None
        self.__host: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        if None is not self.__ip:
            yield "ip", self.__ip
        if None is not self.__ttl:
            yield "ttl", self.__ttl
        if None is not self.__rtt:
            yield "rtt", self.__rtt
        if None is not self.__host:
            yield "host", self.__host

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('hop')
        if None is not d.get('ip', None):
            xml.attrib['ipaddr'] = d.get('ip', None)
        if None is not d.get('ttl', None):
            xml.attrib['ttl'] = str(d.get('ttl', None))
        if None is not d.get('rtt', None):
            xml.attrib['rtt'] = d.get('rtt', None)
        if None is not d.get('host', None):
            xml.attrib['host'] = d.get('host', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Hop(Hop.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_ttl(self) -> int:
        return self.__ttl

    def get_rtt(self) -> Union[str, None]:
        return self.__rtt

    def get_ip(self) -> Union[str, None]:
        return self.__ip

    def get_host(self) -> Union[str, None]:
        return self.__host

    def equals(self, other: T) -> bool:
        return isinstance(other, Hop) \
            and self.__ttl == other.get_ttl() \
            and self.__rtt == other.get_rtt() \
            and self.__ip == other.get_ip() \
            and self.__host == other.get_host()

    def __parse_xml(self):
        logging.info('Parsing Hop')
        attr = self.__xml.attrib
        self.__ttl = attr['ttl']
        self.__rtt = attr.get('rtt', None)
        self.__ip = attr.get('ipaddr', None)
        self.__host = attr.get('host', None)

        logging.debug('TTL: "{ttl}"'.format(ttl=self.__ttl))
        logging.debug('RTT: "{rtt}"'.format(rtt=self.__rtt))
        logging.debug('IP: "{ip}"'.format(ip=self.__ip))
        logging.debug('Host: "{host}"'.format(host=self.__host))
