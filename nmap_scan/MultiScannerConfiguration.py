#!/usr/bin/python3
# -*- coding: utf-8
from typing import Union, Callable, List

from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.Report.Report import Report


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


class MultiScannerConfiguration:

    def __init__(self, nmap_args: NmapArgs, scan_methods: List[str],
                 callback_method: Union[Callable[[str, Report, str], None]] = None, use_all_ips: bool = False):
        self.__use_all_ips = use_all_ips
        self.__callback_method = callback_method
        self.__scan_methods = scan_methods
        self.__nmap_args = nmap_args

    def get_callback_method(self) -> Union[Callable[[str, Report, str], None]]:
        return self.__callback_method

    def get_scan_methods(self) -> List[str]:
        return self.__scan_methods

    def get_nmap_args(self) -> NmapArgs:
        return self.__nmap_args

    def get_use_all_ips(self) -> bool:
        return self.__use_all_ips
