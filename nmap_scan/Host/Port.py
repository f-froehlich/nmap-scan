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
from nmap_scan.Host.Service import Service
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Stats.State import State


class Port:

    def __init__(self, xml):
        self.__xml = xml
        self.__protocol = None
        self.__port = None
        self.__state = None
        self.__owner = None
        self.__service = None
        self.__scripts = []
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_protocol(self):
        return self.__protocol

    def get_port(self):
        return self.__port

    def get_state(self):
        return self.__state

    def get_service(self):
        return self.__service

    def get_scripts(self):
        return self.__scripts

    def get_owner(self):
        return self.__owner

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicException('No valid xml is set.')
        logging.info('Parsing Port')
        attr = self.__xml.attrib
        self.__protocol = attr['protocol']
        self.__owner = attr.get('owner', None)
        self.__port = int(attr['portid'])
        logging.debug('Port: "{port}"'.format(port=self.__port))
        logging.debug('Protocol: "{protocol}"'.format(protocol=self.__protocol))
        logging.debug('Owner: "{owner}"'.format(owner=self.__owner))
        self.__state = State(self.__xml.find('state'))
        self.__service = Service(self.__xml.find('service'))

        for script_xml in self.__xml.findall('script'):
            self.__scripts.append(parse(script_xml))
