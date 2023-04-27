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
from nmap_scan.Stats.Status import Status
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union

T = TypeVar('T', bound='State')


class State(Status):

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        Status.__init__(self, xml, validate_xml)
        self.__reason_ip: Union[str, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "state", self.get_state()
        yield "reason", self.get_reason()
        yield "reasonttl", self.get_reason_ttl()
        if None is not self.__reason_ip:
            yield "reasonip", self.__reason_ip

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('state')
        if None is not d.get('state', None):
            xml.attrib['state'] = d.get('state', None)
        if None is not d.get('reason', None):
            xml.attrib['reason'] = d.get('reason', None)
        if None is not d.get('reasonttl', None):
            xml.attrib['reason_ttl'] = str(d.get('reasonttl', None))
        if None is not d.get('reasonip', None):
            xml.attrib['reason_ip'] = d.get('reasonip', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return State(State.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, State) \
            and Status.equals(self, other) \
            and self.__reason_ip == other.get_reason_ip()

    def get_reason_ip(self) -> Union[str, None]:
        return self.__reason_ip

    def __parse_xml(self):
        logging.info('Parsing State')
        attr = self.get_xml().attrib
        self.__reason_ip = attr.get('reason_ip', None)
        logging.debug('Reason IP: "{reason_ip}"'.format(reason_ip=self.__reason_ip))
