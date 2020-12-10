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


from nmap_scan.Exceptions import NmapScanMethodUnknown


class NmapScanMethods:
    TCP = '-sS'
    UDP = '-sU'
    LIST = '-sL'
    PING = '-sn'

    def get_name_of_method(self, method):
        if self.TCP == method:
            return 'TCP'
        elif self.UDP == method:
            return 'UDP'
        elif self.LIST == method:
            return 'LIST'
        elif self.PING == method:
            return 'PING'

        raise NmapScanMethodUnknown('Unknown scan method "{method}" detected'.format(method=method))

    def require_root(self, method):

        privileged = {
            self.UDP: True,
        }
        return privileged.get(method, False)
