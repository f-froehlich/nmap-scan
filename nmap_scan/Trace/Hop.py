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


class Hop:

    def __init__(self, xml):
        self.__xml = xml
        self.__ttl = None
        self.__rtt = None
        self.__ip = None
        self.__host = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_ttl(self):
        return self.__ttl

    def get_rtt(self):
        return self.__rtt

    def get_ip(self):
        return self.__ip

    def get_host(self):
        return self.__host

    def equals(self, other):
        return isinstance(other, Hop) \
               and self.__ttl == other.get_ttl() \
               and self.__rtt == other.get_rtt() \
               and self.__ip == other.get_ip() \
               and self.__host == other.get_host()

    def __parse_xml(self):
        logging.info('Parsing Hop')
        attr = self.__xml.attrib
        self.__ttl = attr['ttl']
        self.__rtt = attr.get('rtt', None)
        self.__ip = attr.get('ipaddr', None)
        self.__host = attr.get('host', None)

        logging.debug('TTL: "{ttl}"'.format(ttl=self.__ttl))
        logging.debug('RTT: "{rtt}"'.format(rtt=self.__rtt))
        logging.debug('IP: "{ip}"'.format(ip=self.__ip))
        logging.debug('Host: "{host}"'.format(host=self.__host))
