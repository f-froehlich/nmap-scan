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

T = TypeVar('T', bound='Time')


class Time:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__srtt: Union[str, None] = None
        self.__rttvar: Union[str, None] = None
        self.__to: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "srtt", self.__srtt
        yield "rttvar", self.__rttvar
        yield "to", self.__to

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('times')
        if None is not d.get('srtt', None):
            xml.attrib['srtt'] = d.get('srtt', None)
        if None is not d.get('rttvar', None):
            xml.attrib['rttvar'] = d.get('rttvar', None)
        if None is not d.get('to', None):
            xml.attrib['to'] = d.get('to', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Time(Time.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, Time) \
            and self.__srtt == other.get_srtt() \
            and self.__rttvar == other.get_rttvar() \
            and self.__to == other.get_to()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_srtt(self) -> str:
        return self.__srtt

    def get_rttvar(self) -> str:
        return self.__rttvar

    def get_to(self) -> str:
        return self.__to

    def __parse_xml(self):
        logging.info('Parsing Time')
        attr = self.__xml.attrib
        self.__srtt = attr['srtt']
        self.__rttvar = attr['rttvar']
        self.__to = attr['to']

        logging.debug('SRTT: "{srtt}"'.format(srtt=self.__srtt))
        logging.debug('RTT var: "{rttvar}"'.format(rttvar=self.__rttvar))
        logging.debug('To: "{to}"'.format(to=self.__to))
