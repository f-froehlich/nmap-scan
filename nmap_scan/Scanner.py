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

from lxml import etree

from nmap_scan.Exceptions.CallbackException import CallbackException
from nmap_scan.Exceptions.LogicException import LogicException
from nmap_scan.Exceptions.NmapExecutionException import NmapExecutionException
from nmap_scan.Exceptions.NmapNotInstalledException import NmapNotInstalledException
from nmap_scan.Exceptions.NmapPasswordRequiredException import NmapPasswordRequiredException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.NmapScanMethods import NmapScanMethods
from nmap_scan.Report.ACKReport import ACKReport
from nmap_scan.Report.ConnectReport import ConnectReport
from nmap_scan.Report.FINReport import FINReport
from nmap_scan.Report.IPReport import IPReport
from nmap_scan.Report.MaimonReport import MaimonReport
from nmap_scan.Report.PingReport import PingReport
from nmap_scan.Report.SCTPCookieReport import SCTPCookieReport
from nmap_scan.Report.SCTPInitReport import SCTPInitReport
from nmap_scan.Report.SynReport import SynReport
from nmap_scan.Report.TCPNullReport import TCPNullReport
from nmap_scan.Report.TCPReport import TCPReport
from nmap_scan.Report.UDPReport import UDPReport
from nmap_scan.Report.WindowReport import WindowReport
from nmap_scan.Report.XmasReport import XmasReport


class Scanner(NmapScanMethods):

    def __init__(self, nmap_args):
        NmapScanMethods.__init__(self)
        self.__nmap_args = nmap_args
        self.__output = {}
        self.__reports = {}
        self.__threads = {}
        self.__has_error = {}
        self.__which_nmap_lock = threading.Lock()
        self.__nmap_path = None

    def get_nmap_args(self):
        return self.__nmap_args

    def set_nmap_path(self, path):
        logging.info('Set nmap path to "{path}", I hop you know what you are doing!'.format(path=path))
        self.__nmap_path = path

    def get_nmap_path(self):

        self.__which_nmap_lock.acquire()
        if None != self.__nmap_path:
            self.__which_nmap_lock.release()
            return self.__nmap_path

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
            raise NmapNotInstalledException()

        executable = stdout.split("\n")[0]
        logging.debug('Found nmap executable "{executable}"'.format(executable=executable))

        self.__nmap_path = executable
        self.__which_nmap_lock.release()
        return self.__nmap_path

    def __run(self, method, callback_method=None):
        if None != self.__output.get(method, None):
            logging.info('Scan already executed, return scan output')
            return self.__reports.get(method)

        logging.info('Perform {method} scan'.format(method=self.get_name_of_method(method)))

        cmd = self.__nmap_args.get_arg_list()
        if self.TCP != method:
            cmd.insert(0, method)
        cmd.insert(0, self.get_nmap_path())
        if self.require_root(method) or self.__nmap_args.require_root():
            cmd.insert(0, 'sudo')

        command = ' '.join(cmd)
        logging.info('Run command "' + command + '"')

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        logging.debug('Command exit with exit code: "{exitcode}"'.format(exitcode=str(proc.returncode)))

        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        logging.debug('stdout: "{stdout}"'.format(stdout=stdout))
        logging.debug('stderr: "{stderr}"'.format(stderr=stderr))
        if 0 != proc.returncode:
            if 'a password is required' in stderr:
                logging.error('Can\'t run sudo without password')

                raise NmapPasswordRequiredException()
            else:
                logging.error('Unknown error proceed during nmap call:')
                logging.error(stderr)
                err = NmapExecutionException(stderr)
                self.__has_error[method] = err
                raise err

        try:
            xml = self.__parse_xml(stdout)
            self.__output[method] = xml

            try:
                if self.TCP == method:
                    report = TCPReport(xml)
                elif self.TCP_NULL == method:
                    report = TCPNullReport(xml)
                elif self.UDP == method:
                    report = UDPReport(xml)
                elif self.PING == method:
                    report = PingReport(xml)
                elif self.SYN == method:
                    report = SynReport(xml)
                elif self.CONNECT == method:
                    report = ConnectReport(xml)
                elif self.ACK == method:
                    report = ACKReport(xml)
                elif self.WINDOW == method:
                    report = WindowReport(xml)
                elif self.MAIMON == method:
                    report = MaimonReport(xml)
                elif self.FIN == method:
                    report = FINReport(xml)
                elif self.IP == method:
                    report = IPReport(xml)
                elif self.XMAS == method:
                    report = XmasReport(xml)
                elif self.SCTP_INIT == method:
                    report = SCTPInitReport(xml)
                elif self.SCTP_COOKIE == method:
                    report = SCTPCookieReport(xml)
                else:
                    raise LogicException(
                        'No report for scan method "{method}" found'.format(method=self.get_name_of_method(method)))
            except Exception as e:
                self.__has_error[method] = e
                raise e

        except NmapXMLParserException as e:
            self.__has_error[method] = e
            raise e
        except Exception as e:
            self.__has_error[method] = e
            raise NmapXMLParserException()

        self.__reports[method] = report

        try:
            if callable(callback_method):
                logging.info('Call callback method for {scan} scan.'.format(scan=self.get_name_of_method(method)))
                callback_method(report, method)

            return report
        except Exception as e:
            self.__has_error[method] = e
            logging.error(
                'Error in callback method for {scan} scan detected.'.format(scan=self.get_name_of_method(method)))
            raise CallbackException(e)

    def __parse_xml(self, stdout):

        parser = etree.XMLParser()
        xml = ElementTree.fromstring(stdout, parser)

        return xml

    def get_report(self, scan_method):
        if None != self.__reports.get(scan_method, None):
            return self.__reports.get(scan_method)

        if None != self.__has_error.get(scan_method, None):
            raise self.__has_error.get(scan_method)

        if None != self.__threads.get(scan_method, None):
            logging.info('scan for "{method}" not finished yet. Waiting for Report'
                         .format(method=self.get_name_of_method(scan_method)))
            return self.wait(scan_method)

        logging.info('No scan for "{method}" initialised'.format(method=self.get_name_of_method(scan_method)))
        return None

    def scan(self, scan_method, callback_method=None):
        self.scan_background(scan_method, callback_method)
        return self.wait(scan_method)

    def scan_background(self, scan_method, callback_method=None):

        if None != self.__threads.get(scan_method, None):
            return self.__threads.get(scan_method)

        logging.info('Starting thread')
        thread = threading.Thread(target=self.__run, args=(scan_method, callback_method,))
        self.__threads[scan_method] = thread
        thread.start()
        return thread

    def wait(self, method):

        thread = self.__threads.get(method, None)
        if None != thread:
            logging.info('Waiting for scan "{method}" to finish'.format(method=self.get_name_of_method(method)))
            thread.join()
            return self.get_report(method)

        logging.info('No scan for "{method}" initialised'.format(method=self.get_name_of_method(method)))
        return None

    def wait_all(self):

        for thread_method in self.__threads:
            logging.info('Waiting for scan "{method}" to finish'.format(method=self.get_name_of_method(thread_method)))
            self.wait(thread_method)

    def scan_tcp(self, callback_method=None):
        return self.scan(NmapScanMethods.TCP, callback_method)

    def scan_tcp_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.TCP, callback_method)

    def scan_tcp_null(self, callback_method=None):
        return self.scan(NmapScanMethods.TCP_NULL, callback_method)

    def scan_tcp_null_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.TCP_NULL, callback_method)

    def scan_udp(self, callback_method=None):
        return self.scan(NmapScanMethods.UDP, callback_method)

    def scan_udp_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.UDP, callback_method)

    def scan_syn(self, callback_method=None):
        return self.scan(NmapScanMethods.SYN, callback_method)

    def scan_syn_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.SYN, callback_method)

    def scan_fin(self, callback_method=None):
        return self.scan(NmapScanMethods.FIN, callback_method)

    def scan_fin_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.FIN, callback_method)

    def scan_ip(self, callback_method=None):
        return self.scan(NmapScanMethods.IP, callback_method)

    def scan_ip_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.IP, callback_method)

    def scan_sctp_init(self, callback_method=None):
        return self.scan(NmapScanMethods.SCTP_INIT, callback_method)

    def scan_sctp_init_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.SCTP_INIT, callback_method)

    def scan_sctp_cookie(self, callback_method=None):
        return self.scan(NmapScanMethods.SCTP_COOKIE, callback_method)

    def scan_sctp_cookie_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.SCTP_COOKIE, callback_method)

    def scan_xmas(self, callback_method=None):
        return self.scan(NmapScanMethods.XMAS, callback_method)

    def scan_xmas_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.XMAS, callback_method)

    def scan_ping(self, callback_method=None):
        return self.scan(NmapScanMethods.PING, callback_method)

    def scan_ping_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.PING, callback_method)

    def scan_connect(self, callback_method=None):
        return self.scan(NmapScanMethods.CONNECT, callback_method)

    def scan_connect_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.CONNECT, callback_method)

    def scan_ack(self, callback_method=None):
        return self.scan(NmapScanMethods.ACK, callback_method)

    def scan_ack_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.ACK, callback_method)

    def scan_window(self, callback_method=None):
        return self.scan(NmapScanMethods.WINDOW, callback_method)

    def scan_window_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.WINDOW, callback_method)

    def scan_maimon(self, callback_method=None):
        return self.scan(NmapScanMethods.MAIMON, callback_method)

    def scan_maimon_background(self, callback_method=None):
        return self.scan_background(NmapScanMethods.MAIMON, callback_method)
