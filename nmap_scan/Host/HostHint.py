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

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Host.HostName import HostName
from nmap_scan.Stats.Status import Status
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union, List

T = TypeVar('T', bound='HostHint')


class HostHint:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__statuses: List[Status] = []
        self.__addresses: List[HostAddress] = []
        self.__hostnames: List[HostName] = []
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "statuses", [dict(e) for e in self.__statuses]
        yield "addresses", [dict(e) for e in self.__addresses]
        yield "hostnames", [dict(e) for e in self.__hostnames]

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('hosthint')
        if None is not d.get('statuses', None):
            for status_dict in d['statuses']:
                xml.append(Status.dict_to_xml(status_dict, validate_xml))
        if None is not d.get('addresses', None):
            for address_dict in d['addresses']:
                xml.append(HostAddress.dict_to_xml(address_dict, validate_xml))
        if None is not d.get('hostnames', None):
            hostnames_xml = etree.Element('hostnames')
            for hostname_dict in d['hostnames']:
                hostnames_xml.append(HostName.dict_to_xml(hostname_dict, validate_xml))
            xml.append(hostnames_xml)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return HostHint(HostHint.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, HostHint) \
            and compare_lists_equal(self.__statuses, other.get_statuses()) \
            and compare_lists_equal(self.__addresses, other.get_addresses()) \
            and compare_lists_equal(self.__hostnames, other.get_hostnames())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_statuses(self) -> List[Status]:
        return self.__statuses

    def get_addresses(self) -> List[HostAddress]:
        return self.__addresses

    def get_hostnames(self) -> List[HostName]:
        return self.__hostnames

    def __parse_xml(self):
        logging.info('Parsing HostHint')

        for xml in self.__xml.findall('status'):
            self.__statuses.append(Status(xml, False))

        for xml in self.__xml.findall('address'):
            self.__addresses.append(HostAddress(xml, False))

        hostnames_xml = self.__xml.find('hostnames')
        if hostnames_xml != None:
            for hostname_xml in hostnames_xml.findall('hostname'):
                self.__hostnames.append(HostName(hostname_xml, False))
