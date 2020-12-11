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
from nmap_scan.Stats.Status import Status


class State(Status):

    def __init__(self, xml):
        Status.__init__(self, xml)
        self.__reason_ip = None
        self.__parse_xml()

    def get_reason_ip(self):
        return self.__reason_ip

    def __parse_xml(self):
        if None == self.get_xml():
            raise LogicError('No valid xml is set.')
        logging.info('Parsing State')
        attr = self.get_xml().attrib
        self.__reason_ip = int(attr['reason_ip']) if None != attr.get('reason_ip', None) else None
        logging.debug('Reason IP: "{reason_ip}"'.format(reason_ip=self.__reason_ip))
