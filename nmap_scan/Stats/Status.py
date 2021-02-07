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


class Status:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__state = None
        self.__reason = None
        self.__reason_ttl = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "state", self.__state
        yield "reason", self.__reason
        yield "reasonttl", self.__reason_ttl

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('status')
        if None != d.get('state', None):
            xml.attrib['state'] = d.get('state', None)
        if None != d.get('reason', None):
            xml.attrib['reason'] = d.get('reason', None)
        if None != d.get('reasonttl', None):
            xml.attrib['reason_ttl'] = str(d.get('reasonttl', None))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return Status(Status.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, Status) \
               and self.__state == other.get_state() \
               and self.__reason == other.get_reason() \
               and self.__reason_ttl == other.get_reason_ttl()

    def get_xml(self):
        return self.__xml

    def get_state(self):
        return self.__state

    def get_reason(self):
        return self.__reason

    def get_reason_ttl(self):
        return self.__reason_ttl

    def __parse_xml(self):
        logging.info('Parsing Status')
        attr = self.__xml.attrib
        self.__state = attr['state']
        self.__reason = attr['reason']
        self.__reason_ttl = int(attr['reason_ttl'])
        logging.debug('State: "{state}"'.format(state=self.__state))
        logging.debug('Reason: "{reason}"'.format(reason=self.__reason))
        logging.debug('Reason TTL: "{reason_ttl}"'.format(reason_ttl=self.__reason_ttl))
