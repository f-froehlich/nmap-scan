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


class OSUsedPort:

    def __init__(self, xml):
        self.__xml = xml
        self.__state = None
        self.__proto = None
        self.__port = None
        self.__parse_xml()

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
