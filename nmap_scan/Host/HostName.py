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


class HostName:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__name = None
        self.__type = None
        self.__parse_xml()  #

    def __iter__(self):
        yield "name", self.__name
        yield "type", self.__type

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('hostname')

        if None != d.get('name', None):
            xml.attrib['name'] = d.get('name', None)
        if None != d.get('type', None):
            xml.attrib['type'] = d.get('type', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return HostName(HostName.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, HostName) \
               and self.__name == other.get_name() \
               and self.__type == other.get_type()

    def get_xml(self):
        return self.__xml

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def __parse_xml(self):
        logging.info('Parsing HostName')
        attr = self.__xml.attrib
        self.__name = attr.get('name', None)
        self.__type = attr.get('type', None)
        logging.debug('Name: "{name}"'.format(name=self.__name))
        logging.debug('Type: "{type}"'.format(type=self.__type))
