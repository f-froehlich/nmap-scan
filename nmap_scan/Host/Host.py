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

from nmap_scan.Exceptions.LogicException import LogicException
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Host.HostName import HostName
from nmap_scan.Host.Port import Port
from nmap_scan.OS.OS import OS
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Sequence.IPIDSequence import IPIDSequence
from nmap_scan.Sequence.TCPSequence import TCPSequence
from nmap_scan.Sequence.TCPTSSequence import TCPTSSequence
from nmap_scan.Stats.Status import Status
from nmap_scan.Stats.Uptime import Uptime
from nmap_scan.Trace import Trace


class Host:

    def __init__(self, xml):
        self.__xml = xml
        self.__start_time = None
        self.__end_time = None
        self.__status = None
        self.__comment = None
        self.__os = None
        self.__addresses = []
        self.__uptimes = []
        self.__smurfs = []
        self.__hostscripts = []
        self.__times = []
        self.__traces = []
        self.__distances = []
        self.__tcpsequences = []
        self.__tcptssequences = []
        self.__ipidsequences = []
        self.__ports = []
        self.__extra_ports = []
        self.__hostnames = []
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_start_time(self):
        return self.__start_time

    def get_end_time(self):
        return self.__end_time

    def get_status(self):
        return self.__status

    def get_comment(self):
        return self.__comment

    def get_addresses(self):
        return self.__addresses

    def get_ports(self):
        return self.__ports

    def get_extra_ports(self):
        return self.__extra_ports

    def get_smurfs(self):
        return self.__smurfs

    def get_host_scripts(self):
        return self.__hostscripts

    def get_times(self):
        return self.__times

    def get_traces(self):
        return self.__traces

    def get_tcp_sequences(self):
        return self.__tcpsequences

    def get_tcpts_sequences(self):
        return self.__tcptssequences

    def get_ipid_sequences(self):
        return self.__ipidsequences

    def get_uptimes(self):
        return self.__uptimes

    def get_distances(self):
        return self.__distances

    def get_os(self):
        return self.__os

    def get_hostnames(self):
        return self.__hostnames

    def __parse_xml(self):
        if None == self.__xml:
            raise LogicException('No valid xml is set.')
        logging.info('Parsing Host')
        attr = self.__xml.attrib
        self.__start_time = int(attr['starttime']) if None != attr.get('starttime', None) else None
        self.__end_time = int(attr['endtime']) if None != attr.get('endtime', None) else None
        self.__comment = attr.get('comment', None)

        logging.debug('Start time: "{time}"'.format(time=self.__start_time))
        logging.debug('End time: "{time}"'.format(time=self.__end_time))
        logging.debug('Comment: "{comment}"'.format(comment=self.__comment))
        for smurf_xml in self.__xml.findall('smurf'):
            logging.debug('Smurf: "{smurf}"'.format(smurf=smurf_xml.attrib['responses']))
            self.__smurfs.append(smurf_xml.attrib['responses'])
        for distance_xml in self.__xml.findall('distance'):
            logging.debug('Distance: "{distance}"'.format(distance=distance_xml.attrib['value']))
            self.__distances.append(int(distance_xml.attrib['value']))

        self.__status = Status(self.__xml.find('status'))

        for addresses_xml in self.__xml.findall('address'):
            self.__addresses.append(HostAddress(addresses_xml))

        hostnames_xml = self.__xml.find('hostnames')
        if hostnames_xml != None:
            for hostname_xml in hostnames_xml.findall('hostname'):
                self.__hostnames.append(HostName(hostname_xml))

        ports_xml = self.__xml.find('ports')
        if ports_xml != None:
            for port_xml in ports_xml.findall('port'):
                self.__ports.append(Port(port_xml))

        for hostscript_xml in self.__xml.findall('hostscript'):
            for script_xml in hostscript_xml.findall('script'):
                self.__hostscripts.append(parse(script_xml))
        for time_xml in self.__xml.findall('time'):
            self.__times.append(time_xml.attrib['responses'])
        for trace_xml in self.__xml.findall('trace'):
            self.__traces.append(Trace(trace_xml))
        for uptime_xml in self.__xml.findall('uptime'):
            self.__uptimes.append(Uptime(uptime_xml))
        for ipidsequence_xml in self.__xml.findall('ipidsequence'):
            self.__ipidsequences.append(IPIDSequence(ipidsequence_xml))
        for tcpsequence_xml in self.__xml.findall('tcpsequence'):
            self.__tcpsequences.append(TCPSequence(tcpsequence_xml))
        for tcptssequence_xml in self.__xml.findall('tcptssequence'):
            self.__tcptssequences.append(TCPTSSequence(tcptssequence_xml))

        os_xml = self.__xml.find('os')
        if os_xml != None:
            self.__os = OS(os_xml)
