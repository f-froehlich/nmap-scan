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
import threading

from nmap_scan.Exceptions.NmapConfigurationException import NmapConfigurationException
from nmap_scan.MultiScannerConfiguration import MultiScannerConfiguration
from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.Scanner import Scanner


class MultiScanner:

    def __init__(self, configurations):
        for configuration in configurations:
            if not isinstance(configuration, MultiScannerConfiguration):
                raise NmapConfigurationException()
        self.__configurations = configurations
        self.__threads = {i: None for i in range(0, len(configurations))}

    def __prepare_real_scan(self, report, thread_id):
        logging.info('Prepare real scan for thread {thread}'.format(thread=thread_id))

        configuration = self.__configurations[thread_id]
        method = configuration.get_scan_method()
        configured_args = configuration.get_nmap_args()

        scanners = []
        for host in report.get_hosts():
            for address in host.get_addresses():
                if address.is_ip():
                    logging.info('Initiate Scan for host with IP "{ip}" in thread {thread}'
                                 .format(ip=address.get_addr(), thread=thread_id))
                    args = configured_args.clone()
                    args.set_hosts([address.get_addr()])
                    scanner = Scanner(args)
                    scanners.append(scanner)

                    def cm(r, s):
                        if None != configuration.get_callback_method():
                            logging.info('Call callback method for "{ip}" in thread {thread}'
                                         .format(ip=address.get_addr(), thread=thread_id))
                            configuration.get_callback_method()(
                                address.get_addr(),
                                r,
                                s
                            )

                    scanner.scan_background(configuration.get_scan_method(), cm)
                    break

        for scanner in scanners:
            scanner.wait_all()

    def __run(self, ping_args, thread_id):
        logging.debug('Start ping scan for thread {thread}'.format(thread=thread_id))
        scanner = Scanner(ping_args)
        report = scanner.scan_ping()
        logging.debug('Finishing ping scan for thread {thread}'.format(thread=thread_id))
        self.__prepare_real_scan(report, thread_id)

    def scan(self):
        logging.info('Execute multi scan')
        thread_id = 0
        for configuration in self.__configurations:
            self.__scan(configuration, thread_id)
            thread_id += 1

        for thread_id in self.__threads:
            thread = self.__threads[thread_id]
            thread.join()

    def __scan(self, configuration, thread_id):
        args = configuration.get_nmap_args()
        args.lock()

        ping_args = NmapArgs(hosts=args.get_hosts(), pn=args.get_pn())

        logging.info('Starting thread {thread}'.format(thread=thread_id))

        thread = threading.Thread(target=self.__run, args=(ping_args, thread_id,))
        self.__threads[thread_id] = thread
        thread.start()
