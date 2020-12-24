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

from nmap_scan.Trace.Hop import Hop


class Trace:

    def __init__(self, xml):
        self.__xml = xml
        self.__hops = []
        self.__proto = None
        self.__port = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_hops(self):
        return self.__hops

    def get_proto(self):
        return self.__proto

    def get_port(self):
        return self.__port

    def equals(self, other):
        status = self.__proto == other.get_proto() \
                 and self.__port == other.get_port() \
                 and len(self.__hops) == len(other.get_hops())

        if status:
            for own_hop in self.__hops:
                exist = False
                for other_hop in other.get_hops():
                    if own_hop.equals(other_hop):
                        exist = True
                        break
                if not exist:
                    status = False
                    break

        return status

    def __parse_xml(self):
        logging.info('Parsing Trace')
        attr = self.__xml.attrib
        self.__port = int(attr['port']) if None != attr.get('port', None) else None
        self.__proto = attr.get('proto', None)

        logging.debug('Port: "{port}"'.format(port=self.__port))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))

        for xml in self.__xml.findall('hop'):
            self.__hops.append(Hop(xml))
