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


class OSUsedPort:

    def __init__(self, xml, validate_xml=True):
        if validate_xml:
            validate(xml)
        self.__xml = xml
        self.__state = None
        self.__proto = None
        self.__port = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "state", self.__state
        yield "proto", self.__proto
        yield "port", self.__port

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('portused')
        if None != d.get('state', None):
            xml.attrib['state'] = d.get('state', None)
        if None != d.get('proto', None):
            xml.attrib['proto'] = d.get('proto', None)
        if None != d.get('port', None):
            xml.attrib['portid'] = str(d.get('port', None))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return OSUsedPort(OSUsedPort.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, OSUsedPort) \
               and self.__state == other.get_state() \
               and self.__proto == other.get_proto() \
               and self.__port == other.get_port()

    def get_xml(self):
        return self.__xml

    def get_port(self):
        return self.__port

    def get_proto(self):
        return self.__proto

    def get_state(self):
        return self.__state

    def __parse_xml(self):
        logging.info('Parsing OSUsedPort')

        attr = self.__xml.attrib
        self.__state = attr['state']
        self.__proto = attr['proto']
        self.__port = int(attr['portid'])

        logging.debug('State: "{state}"'.format(state=self.__state))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))
        logging.debug('Port: "{port}"'.format(port=self.__port))
