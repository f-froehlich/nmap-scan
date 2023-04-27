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

from lxml import etree

from nmap_scan.CompareHelper import compare_lists_equal, compare_lists, compare_script_maps
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Host.HostName import HostName
from nmap_scan.Host.Port import Port
from nmap_scan.OS.OS import OS
from nmap_scan.Scripts.Script import Script
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Sequence.IPIDSequence import IPIDSequence
from nmap_scan.Sequence.TCPSequence import TCPSequence
from nmap_scan.Sequence.TCPTSSequence import TCPTSSequence
from nmap_scan.Stats.ExtraPort import ExtraPort
from nmap_scan.Stats.Status import Status
from nmap_scan.Stats.Time import Time
from nmap_scan.Stats.Uptime import Uptime
from nmap_scan.Trace.Trace import Trace
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union, List

T = TypeVar('T', bound='Host')


class Host:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__start_time: Union[int, None] = None
        self.__end_time: Union[int, None] = None
        self.__status: Union[str, None] = None
        self.__comment: Union[str, None] = None
        self.__os: List[OS] = []
        self.__addresses: List[HostAddress] = []
        self.__uptimes: List[Uptime] = []
        self.__smurfs: List[int] = []
        self.__hostscripts: Dict[str, Union[List[Script], Script]] = {}
        self.__times: List[Time] = []
        self.__traces: List[Trace] = []
        self.__distances: List[int] = []
        self.__tcpsequences: List[TCPSequence] = []
        self.__tcptssequences: List[TCPTSSequence] = []
        self.__ipidsequences: List[IPIDSequence] = []
        self.__ports: List[Port] = []
        self.__extraports: List[ExtraPort] = []
        self.__open_ports: Union[List[Port], None] = None
        self.__closed_ports: Union[List[Port], None] = None
        self.__filtered_ports: Union[List[Port], None] = None
        self.__unfiltered_ports: Union[List[Port], None] = None
        self.__hostnames: List[HostName] = []
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        if None is not self.__start_time:
            yield "starttime", self.__start_time
        if None is not self.__end_time:
            yield "endtime", self.__end_time
        if None is not self.__comment:
            yield "comment", self.__comment
        yield "distances", self.__distances
        yield "smurfs", self.__smurfs
        yield "status", dict(self.__status)
        yield "addresses", [dict(e) for e in self.__addresses]
        yield "os", [dict(e) for e in self.__os]
        yield "uptime", [dict(e) for e in self.__uptimes]
        yield "times", [dict(e) for e in self.__times]
        yield "traces", [dict(e) for e in self.__traces]
        yield "tcpsequence", [dict(e) for e in self.__tcpsequences]
        yield "tcptssequence", [dict(e) for e in self.__tcptssequences]
        yield "ipidsequence", [dict(e) for e in self.__ipidsequences]
        yield "ports", [dict(e) for e in self.__ports]
        yield "extraports", [dict(e) for e in self.__extraports]
        yield "hostnames", [dict(e) for e in self.__hostnames]

        hostscripts = []
        for id in self.__hostscripts:
            script = self.__hostscripts[id]
            if isinstance(script, Script):
                hostscripts.append(dict(script))
            elif isinstance(script, list):
                for s in script:
                    hostscripts.append(dict(s))

        yield "hostscripts", hostscripts

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('host')
        ports_xml = etree.Element('ports')
        if None is not d.get('starttime', None):
            xml.attrib['starttime'] = str(d.get('starttime', None))
        if None is not d.get('endtime', None):
            xml.attrib['endtime'] = str(d.get('endtime', None))
        if None is not d.get('comment', None):
            xml.attrib['comment'] = d.get('comment', None)

        if None is not d.get('status', None):
            xml.append(Status.dict_to_xml(d['status'], validate_xml))

        if None is not d.get('addresses', None):
            for c in d['addresses']:
                xml.append(HostAddress.dict_to_xml(c, validate_xml))
        if None is not d.get('os', None):
            for c in d['os']:
                xml.append(OS.dict_to_xml(c, validate_xml))
        if None is not d.get('uptime', None):
            for c in d['uptime']:
                xml.append(Uptime.dict_to_xml(c, validate_xml))

        if None is not d.get('traces', None):
            for c in d['traces']:
                xml.append(Trace.dict_to_xml(c, validate_xml))
        if None is not d.get('tcpsequence', None):
            for c in d['tcpsequence']:
                xml.append(TCPSequence.dict_to_xml(c, validate_xml))
        if None is not d.get('tcptssequence', None):
            for c in d['tcptssequence']:
                xml.append(TCPTSSequence.dict_to_xml(c, validate_xml))
        if None is not d.get('ipidsequence', None):
            for c in d['ipidsequence']:
                xml.append(IPIDSequence.dict_to_xml(c, validate_xml))
        if None is not d.get('distances', None):
            for distance_dict in d['distances']:
                distance_xml = etree.Element('distance')
                distance_xml.attrib['value'] = str(distance_dict)
                xml.append(distance_xml)

        if None is not d.get('extraports', None):
            for c in d['extraports']:
                ports_xml.append(ExtraPort.dict_to_xml(c, validate_xml))
        if None is not d.get('ports', None):
            for c in d['ports']:
                ports_xml.append(Port.dict_to_xml(c, validate_xml))
        xml.append(ports_xml)
        if None is not d.get('hostnames', None):
            hostnames_xml = etree.Element('hostnames')
            for hostname_dict in d['hostnames']:
                hostnames_xml.append(HostName.dict_to_xml(hostname_dict, validate_xml))
            xml.append(hostnames_xml)

        if None is not d.get('hostscripts', None):
            for script_dict in d['hostscripts']:
                hostscript_xml = etree.Element('hostscript')
                hostscript_xml.append(Script.dict_to_xml(script_dict, validate_xml))
                xml.append(hostscript_xml)

        if None is not d.get('smurfs', None):
            for smurf in d['smurfs']:
                smurf_xml = etree.Element('smurf')
                smurf_xml.attrib['responses'] = str(smurf)
                xml.append(smurf_xml)

        if None is not d.get('times', None):
            for time_xml in d['times']:
                xml.append(Time.dict_to_xml(time_xml, validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Host(Host.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, Host) \
            and self.__start_time == other.get_start_time() \
            and self.__end_time == other.get_end_time() \
            and self.__status.equals(other.get_status()) \
            and self.__comment == other.get_comment() \
            and compare_lists_equal(self.__os, other.get_os()) \
            and compare_lists_equal(self.__addresses, other.get_addresses()) \
            and compare_lists_equal(self.__uptimes, other.get_uptimes()) \
            and compare_lists_equal(self.__hostnames, other.get_hostnames()) \
            and compare_lists_equal(self.__ports, other.get_ports()) \
            and compare_lists_equal(self.__extraports, other.get_extraports()) \
            and compare_lists_equal(self.__traces, other.get_traces()) \
            and compare_lists_equal(self.__ipidsequences, other.get_ipid_sequences()) \
            and compare_lists_equal(self.__tcpsequences, other.get_tcp_sequences()) \
            and compare_lists_equal(self.__tcptssequences, other.get_tcpts_sequences()) \
            and compare_lists_equal(self.__times, other.get_times()) \
            and compare_lists(self.__distances, other.get_distances()) \
            and compare_lists(self.__smurfs, other.get_smurfs()) \
            and compare_script_maps(self.__hostscripts, other.get_host_scripts())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_start_time(self) -> Union[int, None]:
        return self.__start_time

    def get_end_time(self) -> Union[int, None]:
        return self.__end_time

    def get_status(self) -> Union[str, None]:
        return self.__status

    def get_comment(self) -> Union[int, None]:
        return self.__comment

    def get_addresses(self) -> List[HostAddress]:
        return self.__addresses

    def has_ipv4(self, ip: str) -> bool:
        for address in self.__addresses:
            if address.is_ipv4() and ip == address.get_addr():
                return True
        return False

    def has_ipv6(self, ip: str) -> bool:
        for address in self.__addresses:
            if address.is_ipv6() and ip == address.get_addr():
                return True
        return False

    def has_ip(self, ip: str) -> bool:
        for address in self.__addresses:
            if (address.is_ipv4() or address.is_ipv6()) and ip == address.get_addr():
                return True
        return False

    def has_mac(self, mac: str):
        for address in self.__addresses:
            if address.is_mac() and mac == address.get_addr():
                return True
        return False

    def get_ports(self) -> List[Port]:
        return self.__ports

    def get_extraports(self) -> List[ExtraPort]:
        return self.__extraports

    def get_smurfs(self) -> List[int]:
        return self.__smurfs

    def get_host_scripts(self) -> Dict[str, Union[List[Script], Script]]:
        return self.__hostscripts

    def get_times(self) -> List[Time]:
        return self.__times

    def get_traces(self) -> List[Trace]:
        return self.__traces

    def get_tcp_sequences(self) -> List[TCPSequence]:
        return self.__tcpsequences

    def get_tcpts_sequences(self) -> List[TCPTSSequence]:
        return self.__tcptssequences

    def get_ipid_sequences(self) -> List[IPIDSequence]:
        return self.__ipidsequences

    def get_uptimes(self) -> List[Uptime]:
        return self.__uptimes

    def get_distances(self) -> List[int]:
        return self.__distances

    def get_os(self) -> List[OS]:
        return self.__os

    def get_hostnames(self) -> List[HostName]:
        return self.__hostnames

    def get_open_ports(self) -> List[Port]:
        if None is self.__open_ports:
            self.__open_ports = [p for p in self.__ports if p.is_open()]
        return self.__open_ports

    def get_closed_ports(self) -> List[Port]:
        if None is self.__closed_ports:
            self.__closed_ports = [p for p in self.__ports if p.is_closed()]
        return self.__closed_ports

    def get_filtered_ports(self) -> List[Port]:
        if None is self.__filtered_ports:
            self.__filtered_ports = [p for p in self.__ports if p.is_filtered()]
        return self.__filtered_ports

    def get_unfiltered_ports(self) -> List[Port]:
        if None is self.__unfiltered_ports:
            self.__unfiltered_ports = [p for p in self.__ports if p.is_unfiltered()]
        return self.__unfiltered_ports

    def get_ports_with_ids(self, port_ids: List[int]) -> List[Port]:
        return self.__get_ports_with_ids(port_ids, self.__ports)

    def get_open_ports_with_ids(self, port_ids: List[int]) -> List[Port]:
        return self.__get_ports_with_ids(port_ids, self.get_open_ports())

    def get_closed_ports_with_ids(self, port_ids: List[int]) -> List[Port]:
        return self.__get_ports_with_ids(port_ids, self.get_closed_ports())

    def get_filtered_ports_with_ids(self, port_ids: List[int]) -> List[Port]:
        return self.__get_ports_with_ids(port_ids, self.get_filtered_ports())

    def get_unfiltered_ports_with_ids(self, port_ids: List[int]) -> List[Port]:
        return self.__get_ports_with_ids(port_ids, self.get_unfiltered_ports())

    def __get_ports_with_ids(self, port_ids: List[int], search_ports: List[Port]) -> List[Port]:
        ports = []
        for port in search_ports:
            if port.get_port() in port_ids:
                ports.append(port)

        return ports

    def get_ports_with_script(self, script_id: str) -> List[Port]:
        return self.get_ports_with_scripts([script_id])

    def get_ports_with_scripts(self, script_ids: List[str]) -> List[Port]:
        return self.__get_ports_with_scripts(script_ids, self.__ports)

    def get_open_ports_with_script(self, script_id: str) -> List[Port]:
        return self.get_open_ports_with_scripts([script_id])

    def get_open_ports_with_scripts(self, script_ids: List[str]) -> List[Port]:
        return self.__get_ports_with_scripts(script_ids, self.get_open_ports())

    def get_closed_ports_with_script(self, script_id: str) -> List[Port]:
        return self.get_closed_ports_with_scripts([script_id])

    def get_closed_ports_with_scripts(self, script_ids: List[str]) -> List[Port]:
        return self.__get_ports_with_scripts(script_ids, self.get_closed_ports())

    def get_filtered_ports_with_script(self, script_id: str) -> List[Port]:
        return self.get_filtered_ports_with_scripts([script_id])

    def get_filtered_ports_with_scripts(self, script_ids: List[str]) -> List[Port]:
        return self.__get_ports_with_scripts(script_ids, self.get_filtered_ports())

    def get_unfiltered_ports_with_script(self, script_id: str) -> List[Port]:
        return self.get_unfiltered_ports_with_scripts([script_id])

    def get_unfiltered_ports_with_scripts(self, script_ids: List[str]) -> List[Port]:
        return self.__get_ports_with_scripts(script_ids, self.get_unfiltered_ports())

    def __get_ports_with_scripts(self, script_ids: List[str], search_ports: List[Port]):
        ports = []
        for port in search_ports:
            for script_id in script_ids:
                if port.has_script(script_id):
                    ports.append(port)
                    break

        return ports

    def has_port(self, port_id: int) -> bool:
        return self.__has_port(port_id, self.__ports)

    def has_port_open(self, port_id: int) -> bool:
        return self.__has_port(port_id, self.get_open_ports())

    def has_port_closed(self, port_id: int) -> bool:
        return self.__has_port(port_id, self.get_closed_ports())

    def has_port_filtered(self, port_id: int) -> bool:
        return self.__has_port(port_id, self.get_filtered_ports())

    def has_port_unfiltered(self, port_id: int) -> bool:
        return self.__has_port(port_id, self.get_unfiltered_ports())

    def __has_port(self, port_id: int, search_ports: List[Port]) -> bool:
        for port in search_ports:
            if port_id == port.get_port():
                return True
        return False

    def get_port(self, port_id: int) -> Union[Port, None]:
        return self.__get_port(port_id, self.__ports)

    def get_port_open(self, port_id: int) -> Union[Port, None]:
        return self.__get_port(port_id, self.get_open_ports())

    def get_port_closed(self, port_id: int) -> Union[Port, None]:
        return self.__get_port(port_id, self.get_closed_ports())

    def get_port_filtered(self, port_id: int) -> Union[Port, None]:
        return self.__get_port(port_id, self.get_filtered_ports())

    def get_port_unfiltered(self, port_id: int) -> Union[Port, None]:
        return self.__get_port(port_id, self.get_unfiltered_ports())

    def __get_port(self, port_id: int, search_ports: List[Port]) -> Union[Port, None]:
        for port in search_ports:
            if port_id == port.get_port():
                return port
        return None

    def has_hostscript(self, script_id: str) -> bool:
        return None is not self.__hostscripts.get(script_id, None)

    def get_hostscript(self, script_id: str) -> Union[Script, None]:
        return self.__hostscripts.get(script_id, None)

    def is_up(self) -> bool:
        return 'up' == self.__status.get_state()

    def is_down(self)-> bool:
        return 'down' == self.__status.get_state()

    def is_unknown(self)-> bool:
        return 'unknown' == self.__status.get_state()

    def is_skipped(self)-> bool:
        return 'skipped' == self.__status.get_state()

    def __parse_xml(self):

        logging.info('Parsing Host')
        attr = self.__xml.attrib
        self.__start_time = int(attr['starttime']) if None is not attr.get('starttime', None) else None
        self.__end_time = int(attr['endtime']) if None is not attr.get('endtime', None) else None
        self.__comment = attr.get('comment', None)

        logging.debug('Start time: "{time}"'.format(time=self.__start_time))
        logging.debug('End time: "{time}"'.format(time=self.__end_time))
        logging.debug('Comment: "{comment}"'.format(comment=self.__comment))
        for smurf_xml in self.__xml.findall('smurf'):
            logging.debug('Smurf: "{smurf}"'.format(smurf=smurf_xml.attrib['responses']))
            self.__smurfs.append(int(smurf_xml.attrib['responses']))
        for distance_xml in self.__xml.findall('distance'):
            logging.debug('Distance: "{distance}"'.format(distance=distance_xml.attrib['value']))
            self.__distances.append(int(distance_xml.attrib['value']))

        self.__status = Status(self.__xml.find('status'))

        for addresses_xml in self.__xml.findall('address'):
            self.__addresses.append(HostAddress(addresses_xml, False))

        hostnames_xml = self.__xml.find('hostnames')
        if hostnames_xml != None:
            for hostname_xml in hostnames_xml.findall('hostname'):
                self.__hostnames.append(HostName(hostname_xml, False))

        ports_xml = self.__xml.find('ports')
        if ports_xml != None:
            for port_xml in ports_xml.findall('port'):
                self.__ports.append(Port(port_xml, False))
            for extraports_xml in ports_xml.findall('extraports'):
                self.__extraports.append(ExtraPort(extraports_xml, False))

        for hostscript_xml in self.__xml.findall('hostscript'):
            for script_xml in hostscript_xml.findall('script'):
                script = parse(script_xml, False)
                existing_script = self.__hostscripts.get(script.get_id(), None)
                if None is existing_script:
                    self.__hostscripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__hostscripts[script.get_id()].append(script)
                else:
                    self.__hostscripts[script.get_id()] = [existing_script, script]

        for time_xml in self.__xml.findall('times'):
            self.__times.append(Time(time_xml, False))
        for trace_xml in self.__xml.findall('trace'):
            self.__traces.append(Trace(trace_xml, False))
        for uptime_xml in self.__xml.findall('uptime'):
            self.__uptimes.append(Uptime(uptime_xml, False))
        for ipidsequence_xml in self.__xml.findall('ipidsequence'):
            self.__ipidsequences.append(IPIDSequence(ipidsequence_xml, False))
        for tcpsequence_xml in self.__xml.findall('tcpsequence'):
            self.__tcpsequences.append(TCPSequence(tcpsequence_xml, False))
        for tcptssequence_xml in self.__xml.findall('tcptssequence'):
            self.__tcptssequences.append(TCPTSSequence(tcptssequence_xml, False))
        for os_xml in self.__xml.findall('os'):
            self.__os.append(OS(os_xml, False))
