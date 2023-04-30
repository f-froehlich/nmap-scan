#!/usr/bin/python3
# -*- coding: utf-8

from nmap_scan.MultiScannerConfiguration import MultiScannerConfiguration


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


class MultiScannerError:

    def __init__(self, configuration: MultiScannerConfiguration, address: str, exception: Exception):
        self.__exception = exception
        self.__address = address
        self.__configuration = configuration

    def get_exception(self) -> Exception:
        return self.__exception

    def get_address(self) -> str:
        return self.__address

    def get_configuration(self) -> MultiScannerConfiguration:
        return self.__configuration
