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

from nmap_scan.Exceptions import LogicError
from nmap_scan.OS.OSClass import OSClass


class OSMatch:

    def __init__(self, xml):
        self.__xml = xml
        self.__os_classes = []
        self.__name = None
        self.__accuracy = None
        self.__line = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_os_classes(self):
        return self.__os_classes

    def get_name(self):
        return self.__name

    def get_line(self):
        return self.__line

    def get_accuracy(self):
        return self.__accuracy

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicError('No valid xml is set.')
        logging.info('Parsing OSMatch')

        attr = self.__xml.attrib
        self.__name = attr['name']
        self.__line = int(attr['line'])
        self.__accuracy = int(attr['accuracy'])

        logging.debug('Name: "{name}"'.format(name=self.__name))
        logging.debug('Accuracy: "{accuracy}"'.format(accuracy=self.__accuracy))
        logging.debug('Line: "{line}"'.format(line=self.__line))

        for xml in self.__xml.findall('osclass'):
            self.__os_classes.append(OSClass(xml))
