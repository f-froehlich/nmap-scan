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

from nmap_scan.CompareHelper import compare_lists_equal, compare_lists
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.OS.OSMatch import OSMatch
from nmap_scan.OS.OSUsedPort import OSUsedPort
from nmap_scan.Validator import validate


class OS:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__used_ports = []
        self.__os_matches = []
        self.__os_fingerprints = []
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "portused", [dict(e) for e in self.__used_ports]
        yield "osmatch", [dict(e) for e in self.__os_matches]
        yield "osfingerprint", self.__os_fingerprints

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('os')

        if None != d.get('portused', None):
            for portused_dict in d['portused']:
                xml.append(OSUsedPort.dict_to_xml(portused_dict, validate_xml))
        if None != d.get('osmatch', None):
            for osmatch_dict in d['osmatch']:
                xml.append(OSMatch.dict_to_xml(osmatch_dict, validate_xml))

        if None != d.get('osfingerprint', None):
            for osfingerprint in d['osfingerprint']:
                cpe_xml = etree.Element('osfingerprint')
                cpe_xml.attrib['fingerprint'] = osfingerprint
                xml.append(cpe_xml)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return OS(OS.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, OS) \
               and compare_lists_equal(self.__used_ports, other.get_used_ports()) \
               and compare_lists_equal(self.__os_matches, other.get_os_matches()) \
               and compare_lists(self.__os_fingerprints, other.get_os_fingerprints())

    def get_xml(self):
        return self.__xml

    def get_used_ports(self):
        return self.__used_ports

    def get_os_matches(self):
        return self.__os_matches

    def get_os_fingerprints(self):
        return self.__os_fingerprints

    def __parse_xml(self):

        logging.info('Parsing OS')

        for portused_xml in self.__xml.findall('portused'):
            self.__used_ports.append(OSUsedPort(portused_xml))

        for osmatch_xml in self.__xml.findall('osmatch'):
            self.__os_matches.append(OSMatch(osmatch_xml))

        for osfingerprint_xml in self.__xml.findall('osfingerprint'):
            fingerprint = osfingerprint_xml.attrib['fingerprint']
            self.__os_fingerprints.append(fingerprint)
            logging.debug('Fingerprint: "{fingerprint}"'.format(fingerprint=fingerprint))
