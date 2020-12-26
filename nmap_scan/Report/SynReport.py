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
from xml.etree.ElementTree import ElementTree

from lxml import etree

from nmap_scan.Report.Report import Report


class SynReport(Report):

    def __init__(self, xml):
        logging.info('Create Syn Report')
        Report.__init__(self, xml)

    def equals(self, other):
        return isinstance(other, SynReport) and Report.equals(self, other)

    @staticmethod
    def from_file(filepath):
        parser = etree.XMLParser()
        et = ElementTree()
        xml = et.parse(source=filepath, parser=parser)

        return SynReport(xml)
