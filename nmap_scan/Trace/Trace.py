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
from nmap_scan.Trace.Hop import Hop
from nmap_scan.Validator import validate


class Trace:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__hops = []
        self.__proto = None
        self.__port = None
        self.__parse_xml()

    def __iter__(self):
        yield "hops", [dict(h) for h in self.__hops]
        yield "proto", self.__proto
        yield "port", self.__port

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('trace')
        if None != d.get('port', None):
            xml.attrib['port'] = str(d.get('port', None))
        if None != d.get('proto', None):
            xml.attrib['proto'] = d.get('proto', None)

        if None != d.get('hops', None):
            for hop_dict in d['hops']:
                xml.append(Hop.dict_to_xml(hop_dict))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()
        return xml

    @staticmethod
    def from_dict(d):
        try:
            return Trace(Trace.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def get_xml(self):
        return self.__xml

    def get_hops(self):
        return self.__hops

    def get_proto(self):
        return self.__proto

    def get_port(self):
        return self.__port

    def equals(self, other):
        return isinstance(other, Trace) \
               and self.__proto == other.get_proto() \
               and self.__port == other.get_port() \
               and compare_lists_equal(self.__hops, other.get_hops())

    def __parse_xml(self):
        logging.info('Parsing Trace')
        attr = self.__xml.attrib
        self.__port = int(attr['port']) if None != attr.get('port', None) else None
        self.__proto = attr.get('proto', None)

        logging.debug('Port: "{port}"'.format(port=self.__port))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))

        for xml in self.__xml.findall('hop'):
            self.__hops.append(Hop(xml))
