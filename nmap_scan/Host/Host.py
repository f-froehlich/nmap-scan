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
from nmap_scan.Trace.Trace import Trace


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
        self.__hostscripts = {}
        self.__times = []
        self.__traces = []
        self.__distances = []
        self.__tcpsequences = []
        self.__tcptssequences = []
        self.__ipidsequences = []
        self.__ports = []
        self.__open_ports = None
        self.__closed_ports = None
        self.__filtered_ports = None
        self.__unfiltered_ports = None
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

    def has_ipv4(self, ip):
        for address in self.__addresses:
            if address.is_ipv4() and ip == address.get_addr():
                return True
        return False

    def has_ipv6(self, ip):
        for address in self.__addresses:
            if address.is_ipv6() and ip == address.get_addr():
                return True
        return False

    def has_ip(self, ip):
        for address in self.__addresses:
            if (address.is_ipv4() or address.is_ipv6()) and ip == address.get_addr():
                return True
        return False

    def has_mac(self, ip):
        for address in self.__addresses:
            if address.is_mac() and ip == address.get_addr():
                return True
        return False

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

    def get_open_ports(self):
        if None == self.__open_ports:
            self.__open_ports = [p for p in self.__ports if p.is_open()]
        return self.__open_ports

    def get_closed_ports(self):
        if None == self.__closed_ports:
            self.__closed_ports = [p for p in self.__ports if p.is_closed()]
        return self.__closed_ports

    def get_filtered_ports(self):
        if None == self.__filtered_ports:
            self.__filtered_ports = [p for p in self.__ports if p.is_filtered()]
        return self.__filtered_ports

    def get_unfiltered_ports(self):
        if None == self.__unfiltered_ports:
            self.__unfiltered_ports = [p for p in self.__ports if p.is_unfiltered()]
        return self.__unfiltered_ports

    def get_ports_with_ids(self, port_ids):
        return self.__get_ports_with_ids(port_ids, self.__ports)

    def get_open_ports_with_ids(self, port_ids):
        return self.__get_ports_with_ids(port_ids, self.get_open_ports())

    def get_closed_ports_with_ids(self, port_ids):
        return self.__get_ports_with_ids(port_ids, self.get_closed_ports())

    def get_filtered_ports_with_ids(self, port_ids):
        return self.__get_ports_with_ids(port_ids, self.get_filtered_ports())

    def get_unfiltered_ports_with_ids(self, port_ids):
        return self.__get_ports_with_ids(port_ids, self.get_unfiltered_ports())

    def __get_ports_with_ids(self, port_ids, search_ports):
        ports = []
        for port in search_ports:
            if port.get_port() in port_ids:
                ports.append(port)

        return ports

    def get_ports_with_script(self, script_id):
        return self.get_ports_with_scripts(script_id)

    def get_ports_with_scripts(self, script_ids):
        return self.__get_ports_with_scripts(script_ids, self.__ports)

    def get_open_ports_with_script(self, script_id):
        return self.get_open_ports_with_scripts(script_id)

    def get_open_ports_with_scripts(self, script_ids):
        return self.__get_ports_with_scripts(script_ids, self.get_open_ports())

    def get_closed_ports_with_script(self, script_id):
        return self.get_closed_ports_with_scripts(script_id)

    def get_closed_ports_with_scripts(self, script_ids):
        return self.__get_ports_with_scripts(script_ids, self.get_closed_ports())

    def get_filtered_ports_with_script(self, script_id):
        return self.get_filtered_ports_with_scripts(script_id)

    def get_filtered_ports_with_scripts(self, script_ids):
        return self.__get_ports_with_scripts(script_ids, self.get_filtered_ports())

    def get_unfiltered_ports_with_script(self, script_id):
        return self.get_unfiltered_ports_with_scripts(script_id)

    def get_unfiltered_ports_with_scripts(self, script_ids):
        return self.__get_ports_with_scripts(script_ids, self.get_unfiltered_ports())

    def __get_ports_with_scripts(self, script_ids, search_ports):
        ports = []
        for port in search_ports:
            for script_id in script_ids:
                if port.has_script(script_id):
                    ports.append(port)
                    break

        return ports

    def has_port(self, port_id):
        return self.__has_port(port_id, self.__ports)

    def has_port_open(self, port_id):
        return self.__has_port(port_id, self.get_open_ports())

    def has_port_closed(self, port_id):
        return self.__has_port(port_id, self.get_closed_ports())

    def has_port_filtered(self, port_id):
        return self.__has_port(port_id, self.get_filtered_ports())

    def has_port_unfiltered(self, port_id):
        return self.__has_port(port_id, self.get_unfiltered_ports())

    def __has_port(self, port_id, search_ports):
        for port in search_ports:
            if port_id == port.get_port():
                return True
        return False

    def get_port(self, port_id):
        return self.__get_port(port_id, self.__ports)

    def get_port_open(self, port_id):
        return self.__get_port(port_id, self.get_open_ports())

    def get_port_closed(self, port_id):
        return self.__get_port(port_id, self.get_closed_ports())

    def get_port_filtered(self, port_id):
        return self.__get_port(port_id, self.get_filtered_ports())

    def get_port_unfiltered(self, port_id):
        return self.__get_port(port_id, self.get_unfiltered_ports())

    def __get_port(self, port_id, search_ports):
        for port in search_ports:
            if port_id == port.get_port():
                return port
        return None

    def has_hostscript(self, script_id):
        return None != self.__hostscripts.get(script_id, None)

    def get_hostscript(self, script_id):
        return self.__hostscripts.get(script_id, None)

    def is_up(self):
        return 'up' == self.__status.get_state()

    def is_down(self):
        return 'down' == self.__status.get_state()

    def is_unknown(self):
        return 'unknown' == self.__status.get_state()

    def is_skipped(self):
        return 'skipped' == self.__status.get_state()

    def __parse_xml(self):

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
                script = parse(script_xml)
                existing_script = self.__hostscripts.get(script.get_id(), None)
                if None == existing_script:
                    self.__hostscripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__hostscripts[script.get_id()].append(script)
                else:
                    self.__hostscripts[script.get_id()] = [existing_script, script]

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
