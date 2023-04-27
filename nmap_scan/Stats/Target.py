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

T = TypeVar('T', bound='Target')


class Target:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__status: Union[str, None] = None
        self.__reason: Union[str, None] = None
        self.__specification: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        if None is not self.__status:
            yield "status", self.__status
        if None is not self.__reason:
            yield "reason", self.__reason
        yield "specification", self.__specification

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('target')
        if None is not d.get('status', None):
            xml.attrib['status'] = d.get('status', None)
        if None is not d.get('reason', None):
            xml.attrib['reason'] = d.get('reason', None)
        if None is not d.get('specification', None):
            xml.attrib['specification'] = d.get('specification', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Target(Target.dict_to_xml(d))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, Target) \
            and self.__specification == other.get_specification() \
            and self.__status == other.get_status() \
            and self.__reason == other.get_reason()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_status(self) -> Union[str, None]:
        return self.__status

    def get_specification(self) -> str:
        return self.__specification

    def get_reason(self) -> Union[str, None]:
        return self.__reason

    def __parse_xml(self):
        logging.info('Parsing Target')
        attr = self.__xml.attrib
        self.__specification = attr['specification']
        self.__status = attr.get('status', None)
        self.__reason = attr.get('reason', None)

        logging.debug('Specification: "{specification}"'.format(specification=self.__specification))
        logging.debug('Status: "{status}"'.format(status=self.__status))
        logging.debug('Reason: "{reason}"'.format(reason=self.__reason))
