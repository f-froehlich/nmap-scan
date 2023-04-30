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
from typing import TypeVar, Dict, Union
from xml.etree.ElementTree import Element as XMLElement

from lxml import etree

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate

T = TypeVar('T', bound='TaskProgress')


class TaskProgress:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__task: Union[str, None] = None
        self.__time: Union[int, None] = None
        self.__percent: Union[float, None] = None
        self.__remaining: Union[int, None] = None
        self.__etc: Union[int, None] = None
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "task", self.__task
        yield "time", self.__time
        yield "percent", self.__percent
        yield "remaining", self.__remaining
        yield "etc", self.__etc

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('taskprogress')
        if None is not d.get('task', None):
            xml.attrib['task'] = d.get('task', None)
        if None is not d.get('time', None):
            xml.attrib['time'] = str(d.get('time', None))
        if None is not d.get('percent', None):
            xml.attrib['percent'] = str(d.get('percent', None))
        if None is not d.get('remaining', None):
            xml.attrib['remaining'] = d.get('remaining', None)
        if None is not d.get('etc', None):
            xml.attrib['etc'] = d.get('etc', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return TaskProgress(TaskProgress.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, TaskProgress) \
            and self.__task == other.get_task() \
            and self.__time == other.get_time() \
            and self.__percent == other.get_percent() \
            and self.__remaining == other.get_remaining() \
            and self.__etc == other.get_etc()

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_task(self) -> str:
        return self.__task

    def get_time(self) -> int:
        return self.__time

    def get_percent(self) -> float:
        return self.__percent

    def get_remaining(self) -> int:
        return self.__remaining

    def get_etc(self) -> int:
        return self.__etc

    def __parse_xml(self):
        logging.info('Parsing TaskProcess')
        attr = self.__xml.attrib
        self.__task = attr['task']
        self.__time = int(attr['time'])
        self.__percent = float(attr['percent'])
        self.__remaining = attr['remaining']
        self.__etc = attr['etc']

        logging.debug('Task: "{task}"'.format(task=self.__task))
        logging.debug('Time: "{time}"'.format(time=self.__time))
        logging.debug('Percent: "{percent}"'.format(percent=self.__percent))
        logging.debug('Remaining: "{remeining}"'.format(remeining=self.__remaining))
        logging.debug('Etc: "{etc}"'.format(etc=self.__etc))
