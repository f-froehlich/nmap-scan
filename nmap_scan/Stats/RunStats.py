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

from lxml import etree

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate

from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union

T = TypeVar('T', bound='RunStats')


class RunStats:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__time: Union[int, None] = None
        self.__time_str: Union[str, None] = None
        self.__summary: Union[str, None] = None
        self.__elapsed: Union[int, None] = None
        self.__exit: Union[str, None] = None
        self.__errormsg: Union[str, None] = None
        self.__up: Union[int, None] = None
        self.__down: Union[int, None] = None
        self.__total: Union[int, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "time", self.__time
        if None is not self.__time_str:
            yield "timestr", self.__time_str
        if None is not self.__summary:
            yield "summary", self.__summary
        if None is not self.__elapsed:
            yield "elapsed", self.__elapsed
        if None is not self.__exit:
            yield "exit", self.__exit
        if None is not self.__errormsg:
            yield "errormsg", self.__errormsg
        if None is not self.__up:
            yield "up", self.__up
        if None is not self.__down:
            yield "down", self.__down
        if None is not self.__total:
            yield "total", self.__total

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('runstats')
        xml_finished = etree.Element('finished')
        xml_hosts = etree.Element('hosts')
        if None is not d.get('time', None):
            xml_finished.attrib['time'] = str(d.get('time', None))
        if None is not d.get('timestr', None):
            xml_finished.attrib['timestr'] = d.get('timestr', None)
        if None is not d.get('elapsed', None):
            xml_finished.attrib['elapsed'] = str(d.get('elapsed', None))
        if None is not d.get('summary', None):
            xml_finished.attrib['summary'] = d.get('summary', None)
        if None is not d.get('exit', None):
            xml_finished.attrib['exit'] = d.get('exit', None)
        if None is not d.get('errormsg', None):
            xml_finished.attrib['errormsg'] = d.get('errormsg', None)

        if None is not d.get('total', None):
            xml_hosts.attrib['total'] = str(d.get('total', None))
        if None is not d.get('down', None):
            xml_hosts.attrib['down'] = str(d.get('down', None))
        if None is not d.get('up', None):
            xml_hosts.attrib['up'] = str(d.get('up', None))

        xml.append(xml_finished)
        xml.append(xml_hosts)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return RunStats(RunStats.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, RunStats) \
            and self.__time == other.get_time() \
            and self.__time_str == other.get_time_string() \
            and self.__summary == other.get_summary() \
            and self.__elapsed == other.get_elapsed() \
            and self.__exit == other.get_exit() \
            and self.__errormsg == other.get_errormsg() \
            and self.__up == other.get_up() \
            and self.__down == other.get_down() \
            and self.__total == other.get_total()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_time(self) -> int:
        return self.__time

    def get_time_string(self) -> Union[str, None]:
        return self.__time_str

    def get_summary(self) -> Union[str, None]:
        return self.__summary

    def get_elapsed(self) -> Union[int, None]:
        return self.__elapsed

    def get_exit(self) -> Union[str, None]:
        return self.__exit

    def is_success(self) -> bool:
        return 'success' == self.__exit

    def is_error(self) -> bool:
        return 'error' == self.__exit

    def get_errormsg(self) -> Union[str, None]:
        return self.__errormsg

    def get_up(self) -> int:
        return self.__up

    def get_down(self) -> int:
        return self.__down

    def get_total(self) -> int:
        return self.__total

    def __parse_xml(self):
        logging.info('Parsing RunStats')
        attr_finished = self.__xml.find('finished').attrib
        attr_hosts = self.__xml.find('hosts').attrib
        self.__time = int(attr_finished['time'])
        self.__time_str = attr_finished.get('timestr', None)
        self.__elapsed = float(attr_finished['elapsed']) if None is not attr_finished.get('elapsed', None) else None
        self.__summary = attr_finished.get('summary', None)
        self.__exit = attr_finished.get('exit', None)
        self.__errormsg = attr_finished.get('errormsg', None)
        self.__up = int(attr_hosts['up']) if None is not attr_hosts.get('up', None) else None
        self.__down = int(attr_hosts['down']) if None is not attr_hosts.get('down', None) else None
        self.__total = int(attr_hosts['total']) if None is not attr_hosts.get('total', None) else None

        logging.debug('Time: "{time}"'.format(time=self.__time))
        logging.debug('Time string: "{time_str}"'.format(time_str=self.__time_str))
        logging.debug('Elapsed: "{elapsed}"'.format(elapsed=self.__elapsed))
        logging.debug('Sumary: "{summary}"'.format(summary=self.__summary))
        logging.debug('Exit: "{exit}"'.format(exit=self.__exit))
        logging.debug('Error: "{errormsg}"'.format(errormsg=self.__errormsg))
        logging.debug('Up: "{up}"'.format(up=self.__up))
        logging.debug('Down: "{down}"'.format(down=self.__down))
        logging.debug('Total: "{total}"'.format(total=self.__total))
