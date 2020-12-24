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

from nmap_scan.OS.OSMatch import OSMatch
from nmap_scan.OS.OSUsedPort import OSUsedPort


class OS:

    def __init__(self, xml):
        self.__xml = xml
        self.__used_ports = []
        self.__os_matches = []
        self.__os_fingerprints = []
        self.__parse_xml()

    def equals(self, other):
        if not isinstance(other, OS):
            return False

        for own_used_port in self.__used_ports:
            exist = False
            for other_used_port in other.get_used_ports():
                if own_used_port.equals(other_used_port):
                    exist = True
                    break
            if not exist:
                return False

        for other_used_port in other.get_used_ports():
            exist = False
            for own_used_port in self.__used_ports:
                if own_used_port.equals(other_used_port):
                    exist = True
                    break
            if not exist:
                return False

        for own_os_match in self.__os_matches:
            exist = False
            for other_os_match in other.get_os_matches():
                if own_os_match.equals(other_os_match):
                    exist = True
                    break
            if not exist:
                return False

        for other_os_match in other.get_os_matches():
            exist = False
            for own_os_match in self.__os_matches:
                if own_os_match.equals(other_os_match):
                    exist = True
                    break
            if not exist:
                return False

        for own_os_fingerprint in self.__os_fingerprints:
            if own_os_fingerprint not in other.get_os_fingerprints():
                return False

        for other_os_fingerprint in other.get_os_fingerprints():
            if other_os_fingerprint not in self.__os_fingerprints:
                return False

        return True

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
