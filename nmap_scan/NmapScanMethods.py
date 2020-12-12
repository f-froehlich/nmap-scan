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


from nmap_scan.Exceptions.NmapScanMethodUnknownException import NmapScanMethodUnknownException


class NmapScanMethods:
    TCP = ''
    TCP_NULL = '-sN'
    SYN = '-sS'
    UDP = '-sU'
    LIST = '-sL'
    PING = '-sn'
    CONNECT = '-sT'
    ACK = '-sA'
    WINDOW = '-sW'
    MAIMON = '-sM'
    FIN = '-sF'

    def get_name_of_method(self, method):
        if self.TCP == method:
            return 'TCP'
        elif self.TCP_NULL == method:
            return 'TCP_NULL'
        elif self.SYN == method:
            return 'SYN'
        elif self.UDP == method:
            return 'UDP'
        elif self.LIST == method:
            return 'LIST'
        elif self.PING == method:
            return 'PING'
        elif self.CONNECT == method:
            return 'CONNECT'
        elif self.ACK == method:
            return 'ACK'
        elif self.WINDOW == method:
            return 'WINDOW'
        elif self.MAIMON == method:
            return 'MAIMON'
        elif self.FIN == method:
            return 'FIN'

        raise NmapScanMethodUnknownException('Unknown scan method "{method}" detected'.format(method=method))

    def require_root(self, method):

        privileged = {
            self.SYN: True,
            self.UDP: True,
            self.ACK: True,
            self.WINDOW: True,
            self.MAIMON: True,
            self.TCP_NULL: True,
            self.FIN: True,
        }
        return privileged.get(method, False)
