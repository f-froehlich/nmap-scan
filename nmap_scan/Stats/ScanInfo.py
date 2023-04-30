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

T = TypeVar('T', bound='ScanInfo')


class ScanInfo:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__type: Union[str, None] = None
        self.__protocol: Union[str, None] = None
        self.__scan_flags: Union[str, None] = None
        self.__num_services: Union[int, None] = None
        self.__services: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "type", self.__type
        yield "protocol", self.__protocol
        if None is not self.__scan_flags:
            yield "scanflags", self.__scan_flags
        yield "numservices", self.__num_services
        yield "services", self.__services

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('scaninfo')
        if None is not d.get('type', None):
            xml.attrib['type'] = d.get('type', None)
        if None is not d.get('protocol', None):
            xml.attrib['protocol'] = d.get('protocol', None)
        if None is not d.get('scanflags', None):
            xml.attrib['scanflags'] = d.get('scanflags', None)
        if None is not d.get('numservices', None):
            xml.attrib['numservices'] = str(d.get('numservices', None))
        if None is not d.get('services', None):
            xml.attrib['services'] = d.get('services', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return ScanInfo(ScanInfo.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, ScanInfo) \
            and self.__type == other.get_type() \
            and self.__protocol == other.get_protocol() \
            and self.__scan_flags == other.get_scan_flags() \
            and self.__num_services == other.get_num_services() \
            and self.__services == other.get_services()

    def get_type(self) -> str:
        return self.__type

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_protocol(self) -> str:
        return self.__protocol

    def get_num_services(self) -> int:
        return self.__num_services

    def get_services(self) -> str:
        return self.__services

    def get_scan_flags(self) -> Union[str, None]:
        return self.__scan_flags

    def __parse_xml(self):
        logging.info('Parsing Scaninfo')
        attr = self.__xml.attrib
        self.__type = attr['type']
        self.__protocol = attr['protocol']
        self.__num_services = int(attr['numservices'])
        self.__services = attr['services']
        self.__scan_flags = attr.get('scanflags', None)

        logging.debug('Type: "{value}"'.format(value=self.__type))
        logging.debug('Protocol: "{value}"'.format(value=self.__protocol))
        logging.debug('Number of Services: "{value}"'.format(value=self.__num_services))
        logging.debug('Services: "{value}"'.format(value=self.__services))
        logging.debug('Scan flags: "{scanflags}"'.format(scanflags=self.__scan_flags))
