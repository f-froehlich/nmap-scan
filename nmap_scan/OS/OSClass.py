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

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate


class OSClass:

    def __init__(self, xml, validate_xml=True):
        if validate_xml:
            validate(xml)
        self.__xml = xml
        self.__type = None
        self.__vendor = None
        self.__family = None
        self.__generation = None
        self.__accuracy = None
        self.__cpes = []
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        if None != self.__type:
            yield "type", self.__type
        yield "vendor", self.__vendor
        yield "family", self.__family
        if None != self.__generation:
            yield "generation", self.__generation
        yield "accuracy", self.__accuracy
        yield "cpes", self.__cpes

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        xml = etree.Element('osclass')
        if None != d.get('vendor', None):
            xml.attrib['vendor'] = d.get('vendor', None)
        if None != d.get('generation', None):
            xml.attrib['osgen'] = d.get('generation', None)
        if None != d.get('type', None):
            xml.attrib['type'] = d.get('type', None)
        if None != d.get('family', None):
            xml.attrib['osfamily'] = d.get('family', None)
        if None != d.get('accuracy', None):
            xml.attrib['accuracy'] = str(d.get('accuracy', None))

        if None != d.get('cpes', None):
            for cpe in d['cpes']:
                cpe_xml = etree.Element('cpe')
                cpe_xml.text = cpe
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
            return OSClass(OSClass.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, OSClass) \
               and self.__type == other.get_type() \
               and self.__vendor == other.get_vendor() \
               and self.__family == other.get_family() \
               and self.__generation == other.get_generation() \
               and self.__accuracy == other.get_accuracy() \
               and compare_lists(self.__cpes, other.get_cpes())

    def get_xml(self):
        return self.__xml

    def get_type(self):
        return self.__type

    def get_family(self):
        return self.__family

    def get_generation(self):
        return self.__generation

    def get_cpes(self):
        return self.__cpes

    def get_vendor(self):
        return self.__vendor

    def get_accuracy(self):
        return self.__accuracy

    def __parse_xml(self):
        logging.info('Parsing OSClass')
        attr = self.__xml.attrib
        self.__type = attr.get('type', None)
        self.__vendor = attr['vendor']
        self.__family = attr['osfamily']
        self.__generation = attr.get('osgen', None)
        self.__accuracy = int(attr['accuracy'])

        logging.debug('Type: "{type}"'.format(type=self.__type))
        logging.debug('Vendor: "{vendor}"'.format(vendor=self.__vendor))
        logging.debug('Family: "{family}"'.format(family=self.__family))
        logging.debug('Generation: "{generation}"'.format(generation=self.__generation))
        logging.debug('Accuracy: "{accuracy}"'.format(accuracy=self.__accuracy))

        for xml in self.__xml.findall('cpe'):
            logging.debug('CPE: "{cpe}"'.format(cpe=xml.text))
            self.__cpes.append(xml.text)
