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


class RunStats:

    def __init__(self, xml):
        self.__xml = xml
        self.__time = None
        self.__time_str = None
        self.__summary = None
        self.__elapsed = None
        self.__exit = None
        self.__errormsg = None
        self.__up = None
        self.__down = None
        self.__total = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_time(self):
        return self.__time

    def get_time_string(self):
        return self.__time_str

    def get_summary(self):
        return self.__summary

    def get_elapsed(self):
        return self.__elapsed

    def get_exit(self):
        return self.__exit

    def get_errormsg(self):
        return self.__errormsg

    def get_up(self):
        return self.__up

    def get_down(self):
        return self.__down

    def get_total(self):
        return self.__total

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicException('No valid xml is set.')
        logging.info('Parsing RunStats')
        attr_finished = self.__xml.find('finished').attrib
        attr_hosts = self.__xml.find('hosts').attrib
        self.__time = int(attr_finished['time'])
        self.__time_str = attr_finished.get('timestr', None)
        self.__elapsed = attr_finished['elapsed'] if None != attr_finished.get('elapsed', None) else None
        self.__summary = attr_finished.get('summary', None)
        self.__exit = attr_finished.get('exit', None)
        self.__errormsg = attr_finished.get('errormsg', None)
        self.__up = int(attr_hosts['up']) if None != attr_hosts.get('up', None) else None
        self.__down = int(attr_hosts['down']) if None != attr_hosts.get('down', None) else None
        self.__total = int(attr_hosts['total']) if None != attr_hosts.get('total', None) else None

        logging.debug('Time: "{time}"'.format(time=self.__time))
        logging.debug('Time string: "{time_str}"'.format(time_str=self.__time_str))
        logging.debug('Elapsed: "{elapsed}"'.format(elapsed=self.__elapsed))
        logging.debug('Sumary: "{summary}"'.format(summary=self.__summary))
        logging.debug('Exit: "{exit}"'.format(exit=self.__exit))
        logging.debug('Error: "{errormsg}"'.format(errormsg=self.__errormsg))
        logging.debug('Up: "{up}"'.format(up=self.__up))
        logging.debug('Down: "{down}"'.format(down=self.__down))
        logging.debug('Total: "{total}"'.format(total=self.__total))
