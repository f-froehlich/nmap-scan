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


class IPIDSequence:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__class = None
        self.__values = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "class", self.__class
        yield "values", self.__values

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('ipidsequence')
        if None != d.get('class', None):
            xml.attrib['class'] = d.get('class', None)
        if None != d.get('values', None):
            xml.attrib['values'] = d.get('values', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return IPIDSequence(IPIDSequence.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, IPIDSequence) \
               and self.__class == other.get_class() \
               and self.__values == other.get_values()

    def get_xml(self):
        return self.__xml

    def get_class(self):
        return self.__class

    def get_values(self):
        return self.__values

    def __parse_xml(self):
        logging.info('Parsing IPIDSequence')
        attr = self.__xml.attrib
        self.__class = attr['class']
        self.__values = attr['values']

        logging.debug('Class: "{value}"'.format(value=self.__class))
        logging.debug('Values: "{values}"'.format(values=self.__values))
