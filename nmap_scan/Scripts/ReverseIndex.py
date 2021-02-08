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

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Scripts.Script import Script


class ReverseIndex(Script):

    def __init__(self, xml, validate_xml=True):
        self.__xml = xml
        Script.__init__(self, xml, validate_xml)
        self.__port_ip_map = {}
        self.__parse_xml()

    def equals(self, other):
        status = isinstance(other, ReverseIndex) \
                 and Script.equals(self, other) \
                 and len(self.__port_ip_map) == len(other.get_port_ip_map())

        if status:
            other_elements_other = other.get_port_ip_map()
            for other_key in self.__port_ip_map:
                if not compare_lists(self.__port_ip_map[other_key], other_elements_other.get(other_key, [])):
                    return False

        return status

    def get_xml(self):
        return self.__xml

    def get_port_ip_map(self):
        return self.__port_ip_map

    def get_ips_for_port(self, port, proto):
        return self.__port_ip_map.get(port + '/' + proto, [])

    def __parse_xml(self):

        logging.info('Parsing ReverseIndex')

        xml_tables = self.__xml.findall('table')
        for xml_table in xml_tables:
            port_proto = xml_table.attrib.get('key', 'unknown')
            logging.debug('Parsing: "{key}"'.format(key=port_proto))

            elements = []
            for xml_element in xml_table.findall('elem'):
                logging.debug('Found ip: "{element}"'.format(element=xml_element.text))
                elements.append(xml_element.text)

            self.__port_ip_map[port_proto] = self.__port_ip_map.get(port_proto, []) + elements
