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
from nmap_scan.Stats.ExtraReason import ExtraReason
from nmap_scan.Validator import validate


class ExtraPort:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__state = None
        self.__count = None
        self.__reasons = []
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "state", self.__state
        yield "count", self.__count
        yield "reasons", [dict(r) for r in self.__reasons]

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('extraports')
        if None != d.get('state', None):
            xml.attrib['state'] = d.get('state', None)
        if None != d.get('count', None):
            xml.attrib['count'] = str(d.get('count', None))

        if None != d.get('reasons', None):
            for hop_dict in d['reasons']:
                xml.append(ExtraReason.dict_to_xml(hop_dict))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return ExtraPort(ExtraPort.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, ExtraPort) \
               and self.__state == other.get_state() \
               and self.__count == other.get_count() \
               and compare_lists_equal(self.__reasons, other.get_reasons())

    def get_xml(self):
        return self.__xml

    def get_count(self):
        return self.__count

    def get_state(self):
        return self.__state

    def get_reasons(self):
        return self.__reasons

    def __parse_xml(self):
        logging.info('Parsing ExtraPort')
        attr = self.__xml.attrib
        self.__state = attr['state']
        self.__count = int(attr['count'])

        logging.debug('State: "{state}"'.format(state=self.__state))
        logging.debug('Count: "{count}"'.format(count=self.__count))

        for reasons_xml in self.__xml.findall('extrareasons'):
            self.__reasons.append(ExtraReason(reasons_xml))
