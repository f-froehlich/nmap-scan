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

T = TypeVar('T', bound='Uptime')


class Uptime:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__seconds: Union[int, None] = None
        self.__last_boot: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "seconds", self.__seconds
        if None is not self.__last_boot:
            yield "lastboot", self.__last_boot

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('uptime')
        if None is not d.get('lastboot', None):
            xml.attrib['lastboot'] = d.get('lastboot', None)
        if None is not d.get('seconds', None):
            xml.attrib['seconds'] = str(d.get('seconds', None))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Uptime(Uptime.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_last_boot(self) -> Union[str, None]:
        return self.__last_boot

    def get_seconds(self) -> int:
        return self.__seconds

    def equals(self, other: T) -> bool:
        return isinstance(other, Uptime) \
            and self.__seconds == other.get_seconds() \
            and self.__last_boot == other.get_last_boot()

    def __parse_xml(self):
        logging.info('Parsing Uptime')
        attr = self.__xml.attrib
        self.__last_boot = attr.get('lastboot', None)
        self.__seconds = int(attr['seconds'])

        logging.debug('Seconds: "{seconds}"'.format(seconds=self.__seconds))
        logging.debug('Last boot: "{boot}"'.format(boot=self.__last_boot))
