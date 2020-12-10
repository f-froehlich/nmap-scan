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
import subprocess
import threading
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

from _oald.exceptions import NmapNotInstalledError, NmapXMLParserError, NmapExecutionError
from nmap_scan.Exceptions import NmapPasswordRequired
from nmap_scan.NmapArgs import NmapArgs
from nmap_scan.NmapScanMethods import NmapScanMethods
from nmap_scan.Report import TCPReport


class Scanner(NmapArgs, NmapScanMethods):

    def __init__(self):
        NmapArgs.__init__(self)
        NmapScanMethods.__init__(self)
        self.__output = {}
        self.__reports = {}
        self.__threads = {}

    @staticmethod
    def get_nmap_path():
        logging.info('Run command "which nmap"')

        out = subprocess.Popen(['which', 'nmap'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = out.communicate()
        logging.debug('Command exit with exit code: ' + str(out.returncode))

        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        logging.debug('stdout: "{stdout}"'.format(stdout=stdout))
        logging.debug('stderr: "{stderr}"'.format(stderr=stderr))
        if 0 != out.returncode:
            logging.error('Nmap seams not to be installed, command "which nmap" return non zero exit code.')
            logging.debug(stdout)
            logging.debug(stderr)
            raise NmapNotInstalledError()

        executable = stdout.split("\n")[0]
        logging.debug('Found nmap executable "{executable}"'.format(executable=executable))

        return executable

    def __run(self, method):
        if None != self.__output.get(method, None):
            logging.info('Scan already executed, return scan output')
            return self.__reports.get(method)

        logging.info('Perform {method} scan'.format(method=self.get_name_of_method(method)))

        cmd = self.get_arg_list()
        cmd.insert(0, self.get_nmap_path())
        if self.require_root(method):
            cmd.insert(0, 'sudo')

        command = ' '.join(cmd)
        logging.info('Run command "' + command + '"')

        out = subprocess.Popen(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = out.communicate()
        logging.debug('Command exit with exit code: "{exitcode}"'.format(exitcode=str(out.returncode)))

        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        logging.debug('stdout: "{stdout}"'.format(stdout=stdout))
        logging.debug('stderr: "{stderr}"'.format(stderr=stderr))
        if 0 != out.returncode:
            if 'a password is required' in stderr:
                logging.error('Can\'t run sudo without password')

                raise NmapPasswordRequired()
            else:
                logging.error('Unknown error proceed during nmap call:')
                logging.error(stderr)
                raise NmapExecutionError(stderr)

        try:
            xml = ElementTree.fromstring(stdout)
            self.__output[method] = xml

            if self.TCP == method:
                report = TCPReport(xml)

            # todo scan methods

            self.__reports[method] = report

            return report
        except ParseError:
            raise NmapXMLParserError()

    def get_report(self, scan_method):
        if None != self.__reports.get(scan_method, None):
            return self.__reports.get(scan_method)

        if None != self.__threads.get(scan_method, None):
            logging.info('scan for "{method}" not finished yet. Waiting for Report'
                         .format(method=self.get_name_of_method(scan_method)))
            return self.wait(scan_method)

        logging.info('No scan for "{method}" initialised'.format(method=self.get_name_of_method(scan_method)))
        return None

    def scan(self, scan_method):
        self.scan_background(scan_method)
        return self.wait(scan_method)

    def scan_background(self, scan_method):

        if None != self.__threads.get(scan_method, None):
            return self.__threads.get(scan_method)

        logging.info('Starting thread')
        thread = threading.Thread(target=self.__run, args=(scan_method,))
        self.__threads[scan_method] = thread
        thread.start()
        return thread

    def wait(self, method):

        thread = self.__threads.get(method, None)
        if None != thread:
            logging.info('Waiting for scan "{method}" to finish'.format(method=self.get_name_of_method(method)))
            thread.join()
            return self.__reports[method]

        logging.info('No scan for "{method}" initialised'.format(method=self.get_name_of_method(method)))
        return None

    def wait_all(self):

        for thread_method in self.__threads:
            logging.info('Waiting for scan "{method}" to finish'.format(method=self.get_name_of_method(thread_method)))
            self.__threads[thread_method].join()

    def scan_tcp(self):
        return self.scan(NmapScanMethods.TCP)

    def scan_tcp_background(self):
        return self.scan_background(NmapScanMethods.TCP)
