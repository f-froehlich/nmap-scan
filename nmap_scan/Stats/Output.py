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


class Output:

    def __init__(self, xml, validate_xml=True):
        if validate_xml:
            validate(xml)
        self.__xml = xml
        self.__data = None
        self.__type = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        if None != self.__type:
            yield "type", self.__type
        yield "data", self.__data

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('output')
        if None != d.get('type', None):
            xml.attrib['type'] = d.get('type', None)
        if None != d.get('data', None):
            xml.text = d['data']

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return Output(Output.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, Output) \
               and self.__data == other.get_data() \
               and self.__type == other.get_type()

    def get_xml(self):
        return self.__xml

    def get_type(self):
        return self.__type

    def get_data(self):
        return self.__data

    def __parse_xml(self):
        logging.info('Parsing Output')
        attr = self.__xml.attrib
        self.__type = attr.get('type', None)
        self.__data = self.__xml.text

        logging.debug('Type: "{type}"'.format(type=self.__type))
        logging.debug('Data: "{data}"'.format(data=self.__data))
