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

from nmap_scan.Exceptions.LogicException import LogicException


class TCPSequence:

    def __init__(self, xml):
        self.__xml = xml
        self.__index = None
        self.__difficulty = None
        self.__values = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_index(self):
        return self.__index

    def get_difficulty(self):
        return self.__difficulty

    def get_values(self):
        return self.__values

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicException('No valid xml is set.')
        logging.info('Parsing TCPSequence')
        attr = self.__xml.attrib
        self.__index = int(attr['index'])
        self.__difficulty = attr['difficulty']
        self.__values = attr['values']

        logging.debug('Index: "{index}"'.format(index=self.__index))
        logging.debug('Difficulty: "{difficulty}"'.format(difficulty=self.__difficulty))
        logging.debug('Values: "{values}"'.format(values=self.__values))
