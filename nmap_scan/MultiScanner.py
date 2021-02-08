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

import concurrent.futures
import logging
import threading

from nmap_scan.Exceptions.NmapConfigurationException import NmapConfigurationException
from nmap_scan.MultiScannerConfiguration import MultiScannerConfiguration
from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.Scanner import Scanner


class MultiScanner:

    def __init__(self, configurations, max_threads=32):
        for configuration in configurations:
            if not isinstance(configuration, MultiScannerConfiguration):
                raise NmapConfigurationException()
        self.__configurations = configurations
        self.__main_threads = []
        self.__threads = []
        self.__started = False
        self.__finished = False
        self.__reports = []
        self.__errors = []
        self.__main_thread_lock = threading.Lock()
        self.__thread_lock = threading.Lock()
        self.__report_lock = threading.Lock()
        self.__error_lock = threading.Lock()
        self.__nmap_path = None
        self.__thread_pool = None
        self.__max_threads = max_threads

    def set_nmap_path(self, path):
        logging.info('Set nmap path to "{path}", I hop you know what you are doing!'.format(path=path))
        self.__nmap_path = path

    def get_reports(self):
        self.wait()
        return self.__reports

    def get_combined_report(self):
        self.wait()
        if 0 == len(self.__reports):
            return None

        report = self.__reports[0]
        for other_report in self.__reports[1:]:
            report.combine(other_report)

        return report

    def is_finished(self):
        return self.__finished

    def __add_report(self, report):
        self.__report_lock.acquire()
        self.__reports.append(report)
        self.__report_lock.release()

    def __prepare_real_scan(self, report, thread_id, nmap_path):
        logging.info('Prepare real scan for thread {thread}'.format(thread=thread_id))

        configuration = self.__configurations[thread_id]
        configured_args = configuration.get_nmap_args()

        for host in report.get_hosts():
            for address in host.get_addresses():
                if address.is_ip():
                    logging.info('Initiate Scan for host with IP "{ip}" in thread {thread}'
                                 .format(ip=address.get_addr(), thread=thread_id))

                    args = configured_args.clone()
                    args.set_hosts([address.get_addr()])
                    for scan_method in configuration.get_scan_methods():
                        self.__thread_lock.acquire()
                        self.__threads.append(self.__thread_pool.submit(
                            self.__init_scan,
                            args=args,
                            address=address.get_addr(),
                            thread_id=thread_id,
                            configuration=configuration,
                            nmap_path=nmap_path,
                            scan_method=scan_method
                        ))
                        self.__thread_lock.release()
                    if not configuration.get_use_all_ips():
                        break

    def __init_scan(self, args, address, thread_id, configuration, nmap_path, scan_method):
        scanner = Scanner(args)
        scanner.set_nmap_path(nmap_path)

        def cm(r, s, ip=address, tid=thread_id):
            if None != configuration.get_callback_method():
                logging.info('Call callback method for "{ip}" in thread {thread}'
                             .format(ip=ip, thread=tid))
                configuration.get_callback_method()(ip, r, s)

        try:
            report = scanner.scan(scan_method, cm)
            self.__add_report(report)
        except Exception as e:
            self.__add_error(configuration, address, e)

    def __run(self, ping_args, thread_id):
        logging.debug('Start ping scan for thread {thread}'.format(thread=thread_id))
        scanner = Scanner(ping_args)
        scanner.set_nmap_path(self.__nmap_path)
        report = scanner.scan_ping()
        logging.debug('Finishing ping scan for thread {thread}'.format(thread=thread_id))
        self.__prepare_real_scan(report, thread_id, scanner.get_nmap_path())

    def scan(self):
        self.scan_background()
        self.wait()

    def scan_background(self):
        logging.info('Execute multi scan')
        self.__main_thread_lock.acquire()
        if self.__started:
            self.__main_thread_lock.release()
            return
        self.__started = True
        self.__thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.__max_threads)
        self.__main_thread_lock.release()

        thread_id = 0
        for configuration in self.__configurations:
            self.__main_thread_lock.acquire()
            self.__main_threads.append(self.__thread_pool.submit(
                self.__scan,
                configuration=configuration,
                thread_id=thread_id
            ))
            self.__main_thread_lock.release()
            thread_id += 1

    def wait(self):

        if self.__finished:
            return

        for main_thread in self.__main_threads:
            main_thread.result()

        for thread in self.__threads:
            thread.result()

        self.__finished = True
        self.__thread_pool.shutdown()

    def __scan(self, configuration, thread_id):
        args = configuration.get_nmap_args()
        args.lock()

        ping_args = NmapArgs(
            hosts=args.get_hosts(),
            pn=args.get_pn(),
            min_parallelism=args.get_min_parallelism()
        )

        logging.info('Starting thread {thread}'.format(thread=thread_id))
        self.__run(ping_args, thread_id)

    def __add_error(self, configuration, address, exception):
        self.__error_lock.acquire()
        self.__errors.append({'config': configuration, 'address': address, 'exception': exception})
        self.__error_lock.release()

    def get_errors(self):
        self.wait()
        return self.__errors
