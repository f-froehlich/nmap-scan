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

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate


class TaskBegin:

    def __init__(self, xml):
        validate(xml)
        self.__xml = xml
        self.__task = None
        self.__time = None
        self.__extra_info = None
        self.__parse_xml()

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        yield "task", self.__task
        yield "time", self.__time
        if None != self.__extra_info:
            yield "extrainfo", self.__extra_info

    @staticmethod
    def dict_to_xml(d, validate_xml=True):
        from lxml import etree
        xml = etree.Element('taskbegin')
        if None != d.get('task', None):
            xml.attrib['task'] = d.get('task', None)
        if None != d.get('time', None):
            xml.attrib['time'] = str(d.get('time', None))
        if None != d.get('extrainfo', None):
            xml.attrib['extrainfo'] = d.get('extrainfo', None)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d):
        try:
            return TaskBegin(TaskBegin.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other):
        return isinstance(other, TaskBegin) \
               and self.__task == other.get_task() \
               and self.__time == other.get_time() \
               and self.__extra_info == other.get_extra_info()

    def get_xml(self):
        return self.__xml

    def get_task(self):
        return self.__task

    def get_time(self):
        return self.__time

    def get_extra_info(self):
        return self.__extra_info

    def __parse_xml(self):
        logging.info('Parsing TaskBegin')
        attr = self.__xml.attrib
        self.__task = attr['task']
        self.__time = attr['time']
        self.__extra_info = attr.get('extrainfo', None)

        logging.debug('Task: "{task}"'.format(task=self.__task))
        logging.debug('Time: "{time}"'.format(time=self.__time))
        logging.debug('Extra info: "{info}"'.format(info=self.__extra_info))
