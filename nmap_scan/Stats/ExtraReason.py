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


class ExtraReason:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__reason = None
        self.__count = None
        self.__proto = None
        self.__ports = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "reason", self.__reason
        yield "count", self.__count
        if None != self.__proto:
            yield "proto", self.__proto
        if None != self.__ports:
            yield "ports", self.__ports

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('extrareasons')
        if None != d.get('reason', None):
            xml.attrib['reason'] = d.get('reason', None)
        if None != d.get('count', None):
            xml.attrib['count'] = d.get('count', None)
        if None != d.get('proto', None):
            xml.attrib['proto'] = d.get('proto', None)
        if None != d.get('ports', None):
            xml.attrib['ports'] = d.get('ports', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return ExtraReason(ExtraReason.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, ExtraReason) \
               and self.__reason == other.get_reason() \
               and self.__count == other.get_count() \
               and self.__proto == other.get_proto() \
               and self.__ports == other.get_ports()

    def get_xml(self):
        return self.__xml

    def get_count(self):
        return self.__count

    def get_reason(self):
        return self.__reason

    def get_ports(self):
        return self.__ports

    def get_proto(self):
        return self.__proto

    def __parse_xml(self):
        logging.info('Parsing ExtraReason')
        attr = self.__xml.attrib
        self.__reason = attr['reason']
        self.__count = attr['count']
        self.__proto = attr.get('proto', None)
        self.__ports = attr.get('ports', None)

        logging.debug('Reason: "{reason}"'.format(reason=self.__reason))
        logging.debug('Count: "{count}"'.format(count=self.__count))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))
        logging.debug('Ports: "{ports}"'.format(ports=self.__ports))
