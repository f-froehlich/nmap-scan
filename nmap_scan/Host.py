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
from nmap_scan.HostAddress import HostAddress
from nmap_scan.HostName import HostName
from nmap_scan.Port import Port
from nmap_scan.State import State


class Host:

    def __init__(self, xml):
        self.__xml = xml
        self.__start_time = None
        self.__end_time = None
        self.__state = None
        self.__addresses = []
        self.__ports = []
        self.__hostnames = []
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_start_time(self):
        return self.__start_time

    def get_end_time(self):
        return self.__end_time

    def get_state(self):
        return self.__state

    def get_addresses(self):
        return self.__addresses

    def get_ports(self):
        return self.__ports

    def get_hostnames(self):
        return self.__hostnames

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicError('No valid xml is set.')
        logging.info('Parsing Host')
        attr = self.__xml.attrib
        self.__start_time = int(attr['starttime'])
        self.__end_time = int(attr['endtime'])
        self.__state = State(self.__xml.find('status'))

        for addresses_xml in self.__xml.findall('address'):
            self.__addresses.append(HostAddress(addresses_xml))

        hostnames_xml = self.__xml.find('hostnames')
        if hostnames_xml != None:
            for hostname_xml in hostnames_xml.findall('hostname'):
                self.__hostnames.append(HostName(hostname_xml))

        ports_xml = self.__xml.find('ports')
        if ports_xml != None:
            for port_xml in ports_xml.findall('port'):
                self.__ports.append(Port(port_xml))
