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
import copy
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Union, List, Mapping, Type, TypeVar, Callable, Dict
from xml.etree.ElementTree import ElementTree

import requests
from lxml import etree

from nmap_scan.CompareHelper import compare_lists_equal, compare_script_maps
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Exceptions.ReportCombineException import ReportCombineException
from nmap_scan.Host.Host import Host
from nmap_scan.Host.HostHint import HostHint
from nmap_scan.Host.Port import Port
from nmap_scan.Scripts.Script import Script
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Stats.Output import Output
from nmap_scan.Stats.RunStats import RunStats
from nmap_scan.Stats.ScanInfo import ScanInfo
from nmap_scan.Stats.Target import Target
from nmap_scan.Stats.TaskBegin import TaskBegin
from nmap_scan.Stats.TaskEnd import TaskEnd
from nmap_scan.Stats.TaskProgress import TaskProgress
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement

T = TypeVar('T', bound='Report')


class Report:

    def __init__(self, xml: XMLElement):
        self.__xml: XMLElement = xml
        self.__scanner: Union[str, None] = None
        self.__scanner_args: Union[str, None] = None
        self.__start: Union[int, None] = None
        self.__startstr: Union[str, None] = None
        self.__version: Union[str, None] = None
        self.__profile_name: Union[str, None] = None
        self.__xmloutputversion: Union[str, None] = None
        self.__scaninfos: List[ScanInfo] = []
        self.__targets: List[Target] = []
        self.__outputs: List[Output] = []
        self.__task_progresses: List[TaskProgress] = []
        self.__task_begins: List[TaskBegin] = []
        self.__task_ends: List[TaskEnd] = []
        self.__pre_scripts: Dict[str, Union[Script, List[Script]]] = {}
        self.__post_scripts: Dict[str, Union[Script, List[Script]]] = {}
        self.__verbose_level: Union[int, None] = None
        self.__debugging_level: Union[int, None] = None
        self.__run_stats: Union[RunStats, None] = None
        self.__hosts: List[Host] = []
        self.__host_hints: List[HostHint] = []
        self.__hosts_up: Union[List[Host], None] = None
        self.__hosts_down: Union[List[Host], None] = None
        self.__hosts_unknown: Union[List[Host], None] = None
        self.__hosts_skipped: Union[List[Host], None] = None
        self.__is_combined: bool = False

        self.__parse_xml()

    def __eq__(self, other: T):
        return self.equals(other)

    def __ne__(self, other: T):
        return not self.__eq__(other)

    def __iter__(self):
        yield "scanner", self.__scanner
        yield "version", self.__version
        if None is not self.__xmloutputversion:
            yield "xmloutputversion", self.__xmloutputversion
        if None is not self.__profile_name:
            yield "profile_name", self.__profile_name
        yield "args", self.__scanner_args
        if None is not self.__start:
            yield "start", self.__start
        if None is not self.__startstr:
            yield "startstr", self.__startstr
        if None is not self.__verbose_level:
            yield "verbose", self.__verbose_level
        if None is not self.__debugging_level:
            yield "debugging", self.__debugging_level
        yield "runstats", dict(self.__run_stats)
        yield "scaninfo", [dict(e) for e in self.__scaninfos]
        yield "targets", [dict(e) for e in self.__targets]
        yield "taskbegin", [dict(e) for e in self.__task_begins]
        yield "taskprogress", [dict(e) for e in self.__task_progresses]
        yield "taskend", [dict(e) for e in self.__task_ends]
        yield "hosts", [dict(e) for e in self.__hosts]
        yield "hosthints", [dict(e) for e in self.__host_hints]
        yield "outputs", [dict(e) for e in self.__outputs]

        prescripts = []
        for id in self.__pre_scripts:
            script = self.__pre_scripts[id]
            if isinstance(script, Script):
                prescripts.append(dict(script))
            elif isinstance(script, list):
                for s in script:
                    prescripts.append(dict(s))

        yield "prescripts", prescripts

        postscripts = []
        for id in self.__post_scripts:
            script = self.__post_scripts[id]
            if isinstance(script, Script):
                postscripts.append(dict(script))
            elif isinstance(script, list):
                for s in script:
                    postscripts.append(dict(s))

        yield "postscripts", postscripts

    @staticmethod
    def dict_to_xml(d: Mapping[str, any], validate_xml: bool = True) -> XMLElement:
        xml: XMLElement = etree.Element('nmaprun')

        if None is not d.get('scanner', None):
            xml.attrib['scanner'] = d.get('scanner', None)
        if None is not d.get('version', None):
            xml.attrib['version'] = d.get('version', None)
        if None is not d.get('xmloutputversion', None):
            xml.attrib['xmloutputversion'] = d.get('xmloutputversion', None)
        if None is not d.get('profile_name', None):
            xml.attrib['profile_name'] = d.get('profile_name', None)
        if None is not d.get('args', None):
            xml.attrib['args'] = d.get('args', None)
        if None is not d.get('start', None):
            xml.attrib['start'] = str(d.get('start', None))
        if None is not d.get('startstr', None):
            xml.attrib['startstr'] = d.get('startstr', None)

        if None is not d.get('scaninfo', None):
            for status_dict in d['scaninfo']:
                xml.append(ScanInfo.dict_to_xml(status_dict, validate_xml))

        if None is not d.get('verbose', None):
            verbose_xml = etree.Element('verbose')
            verbose_xml.attrib['level'] = str(d['verbose'])
            xml.append(verbose_xml)

        if None is not d.get('debugging', None):
            debugging_xml = etree.Element('debugging')
            debugging_xml.attrib['level'] = str(d['debugging'])
            xml.append(debugging_xml)

        if None is not d.get('targets', None):
            for e_dict in d['targets']:
                xml.append(Target.dict_to_xml(e_dict, validate_xml))
        if None is not d.get('taskbegin', None):
            for e_dict in d['taskbegin']:
                xml.append(TaskBegin.dict_to_xml(e_dict, validate_xml))
        if None is not d.get('taskprogress', None):
            for e_dict in d['taskprogress']:
                xml.append(TaskProgress.dict_to_xml(e_dict, validate_xml))
        if None is not d.get('taskend', None):
            for e_dict in d['taskend']:
                xml.append(TaskEnd.dict_to_xml(e_dict, validate_xml))

        if None is not d.get('hosthints', None):
            for e_dict in d['hosthints']:
                xml.append(HostHint.dict_to_xml(e_dict, validate_xml))

        if None is not d.get('prescripts', None):
            for script_dict in d['prescripts']:
                script_xml = etree.Element('prescript')
                script_xml.append(Script.dict_to_xml(script_dict, validate_xml))
                xml.append(script_xml)
        if None is not d.get('postscripts', None):
            for script_dict in d['postscripts']:
                script_xml = etree.Element('postscript')
                script_xml.append(Script.dict_to_xml(script_dict, validate_xml))
                xml.append(script_xml)

        if None is not d.get('hosts', None):
            for e_dict in d['hosts']:
                xml.append(Host.dict_to_xml(e_dict, validate_xml))
        if None is not d.get('outputs', None):
            for e_dict in d['outputs']:
                xml.append(Output.dict_to_xml(e_dict, validate_xml))

        if None is not d.get('runstats', None):
            xml.append(RunStats.dict_to_xml(d['runstats'], validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Mapping[str, any]) -> T:
        try:
            return Report(Report.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T):
        return isinstance(other, Report) \
            and self.__scanner == other.get_scanner() \
            and self.__scanner_args == other.get_scanner_args() \
            and self.__start == other.get_start() \
            and self.__startstr == other.get_start_string() \
            and self.__version == other.get_version() \
            and self.__profile_name == other.get_profile_name() \
            and self.__xmloutputversion == other.get_xml_output_version() \
            and self.__verbose_level == other.get_verbose_level() \
            and self.__debugging_level == other.get_debugging_level() \
            and self.__run_stats.equals(other.get_run_stats()) \
            and compare_lists_equal(self.__scaninfos, other.get_scaninfos()) \
            and compare_lists_equal(self.__scaninfos, other.get_scaninfos()) \
            and compare_lists_equal(self.__targets, other.get_targets()) \
            and compare_lists_equal(self.__outputs, other.get_outputs()) \
            and compare_lists_equal(self.__task_progresses, other.get_task_progresses()) \
            and compare_lists_equal(self.__task_begins, other.get_task_begins()) \
            and compare_lists_equal(self.__task_ends, other.get_task_ends()) \
            and compare_lists_equal(self.__hosts, other.get_hosts()) \
            and compare_lists_equal(self.__host_hints, other.get_host_hints()) \
            and compare_script_maps(self.__pre_scripts, other.get_pre_scripts()) \
            and compare_script_maps(self.__post_scripts, other.get_post_scripts())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def is_combined(self) -> bool:
        return self.__is_combined

    def get_scanner(self) -> Union[str, None]:
        return self.__scanner

    def get_scanner_args(self) -> Union[str, None]:
        return self.__scanner_args

    def get_start(self) -> Union[int, None]:
        return self.__start

    def get_start_string(self) -> Union[str, None]:
        return self.__startstr

    def get_version(self) -> Union[str, None]:
        return self.__version

    def get_xml_output_version(self) -> Union[str, None]:
        return self.__xmloutputversion

    def get_profile_name(self) -> Union[str, None]:
        return self.__profile_name

    def get_scaninfos(self) -> List[ScanInfo]:
        return self.__scaninfos

    def get_verbose_level(self) -> Union[int, None]:
        return self.__verbose_level

    def get_debugging_level(self) -> Union[int, None]:
        return self.__debugging_level

    def get_targets(self) -> List[Target]:
        return self.__targets

    def get_outputs(self) -> List[Output]:
        return self.__outputs

    def get_task_progresses(self) -> List[TaskProgress]:
        return self.__task_progresses

    def get_task_begins(self) -> List[TaskBegin]:
        return self.__task_begins

    def get_task_ends(self) -> List[TaskEnd]:
        return self.__task_ends

    def get_run_stats(self) -> Union[RunStats, None]:
        return self.__run_stats

    def get_host_hints(self) -> List[HostHint]:
        return self.__host_hints

    def get_hosts(self) -> List[Host]:
        return self.__hosts

    def get_hosts_up(self) -> List[Host]:
        if None is self.__hosts_up:
            self.__hosts_up = [h for h in self.__hosts if h.is_up()]
        return self.__hosts_up

    def get_hosts_down(self) -> List[Host]:
        if None is self.__hosts_down:
            self.__hosts_down = [h for h in self.__hosts if h.is_down()]
        return self.__hosts_down

    def get_hosts_unknown(self) -> List[Host]:
        if None is self.__hosts_unknown:
            self.__hosts_unknown = [h for h in self.__hosts if h.is_unknown()]
        return self.__hosts_unknown

    def get_hosts_skipped(self) -> List[Host]:
        if None is self.__hosts_skipped:
            self.__hosts_skipped = [h for h in self.__hosts if h.is_skipped()]
        return self.__hosts_skipped

    def get_pre_scripts(self) -> Dict[str, Union[Script, List[Script]]]:
        return self.__pre_scripts

    def has_pre_script(self, pre_script_id) -> bool:
        return None is not self.__pre_scripts.get(pre_script_id, None)

    def get_pre_script(self, pre_script_id) -> Union[Dict[str, Union[List[Script], Script]], None]:
        return self.__pre_scripts.get(pre_script_id, None)

    def get_post_scripts(self) -> Mapping[str, Union[Script, List[Script]]]:
        return self.__post_scripts

    def has_post_script(self, post_script_id) -> bool:
        return None is not self.__post_scripts.get(post_script_id, None)

    def get_post_script(self, post_script_id) -> Union[Dict[str, Union[List[Script], Script]], None]:
        return self.__post_scripts.get(post_script_id, None)

    def get_host_with_port(self, port_id) -> List[Host]:
        return self.get_hosts_with_port([port_id])

    def get_hosts_with_port(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port):
            return True

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_open(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_open(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_open(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_open(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_open(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_closed(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_close(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_closed(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_closed(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_closed(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_filtered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_filtered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_filtered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_filtered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_filtered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_unfiltered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_unfiltered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_unfiltered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_unfiltered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_unfiltered(self, port_ids: List[int]) -> List[Host]:
        def callback(port: Port) -> bool:
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def __get_hosts_with_port(self, port_ids: List[int], search_hosts: List[Host], callback: Callable[[Port], bool]) -> \
            List[Host]:
        hosts: List[Host] = []
        for host in search_hosts:
            if host in hosts:
                continue

            for port_id in port_ids:
                if host.has_port(port_id) and callback(host.get_port(port_id)):
                    hosts.append(host)
                    break

        return hosts

    def get_hosts_with_script(self, script_id: str) -> List[Host]:
        hosts: List[Host] = []
        for host in self.__hosts:
            if host in hosts:
                continue
            host_ports = []
            for port in host.get_ports():
                if port.has_script(script_id):
                    host_ports.append(port)
            if 0 != len(host_ports):
                hosts.append(host)

        return hosts

    def __parse_xml(self):
        self.validate(self.__xml)
        nmaprun = self.get_xml().attrib
        self.__scanner = nmaprun['scanner']
        self.__scanner_args = nmaprun.get('args', None)
        self.__start = int(nmaprun['start']) if None is not nmaprun.get('start', None) else None
        self.__startstr = nmaprun.get('startstr', None)
        self.__version = nmaprun['version']
        self.__xmloutputversion = nmaprun.get('xmloutputversion', None)
        self.__profile_name = nmaprun.get('profile_name', None)

        for host_xml in self.get_xml().findall('host'):
            self.__hosts.append(Host(host_xml, False))

        verbose_xml = self.get_xml().find('verbose')
        if None is not verbose_xml:
            self.__verbose_level = int(verbose_xml.attrib['level']) if None is not verbose_xml.attrib.get(
                'level') else None

        debugging_xml = self.get_xml().find('debugging')
        if None is not debugging_xml:
            self.__debugging_level = int(debugging_xml.attrib['level']) if None is not debugging_xml.attrib.get(
                'level') else None

        run_stats_xml = self.get_xml().find('runstats')
        if None is not run_stats_xml:
            self.__run_stats = RunStats(run_stats_xml, False)

        for scaninfo_xml in self.get_xml().findall('scaninfo'):
            self.__scaninfos.append(ScanInfo(scaninfo_xml, False))

        for target_xml in self.__xml.findall('target'):
            self.__targets.append(Target(target_xml, False))

        for output_xml in self.__xml.findall('output'):
            self.__outputs.append(Output(output_xml, False))

        for task_progress_xml in self.__xml.findall('taskprogress'):
            self.__task_progresses.append(TaskProgress(task_progress_xml, False))

        for task_begin_xml in self.__xml.findall('taskbegin'):
            self.__task_begins.append(TaskBegin(task_begin_xml, False))

        for task_end_xml in self.__xml.findall('taskend'):
            self.__task_ends.append(TaskEnd(task_end_xml, False))

        for hosthint_xml in self.__xml.findall('hosthint'):
            self.__host_hints.append(HostHint(hosthint_xml, False))

        for prescript_xml in self.__xml.findall('prescript'):
            for script_xml in prescript_xml.findall('script'):
                script = parse(script_xml, False)
                existing_script = self.__pre_scripts.get(script.get_id(), None)
                if None is existing_script:
                    self.__pre_scripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__pre_scripts[script.get_id()].append(script)
                else:
                    self.__pre_scripts[script.get_id()] = [existing_script, script]

        for postscript_xml in self.__xml.findall('postscript'):
            for script_xml in postscript_xml.findall('script'):
                script = parse(script_xml, False)
                existing_script = self.__post_scripts.get(script.get_id(), None)
                if None is existing_script:
                    self.__post_scripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__post_scripts[script.get_id()].append(script)
                else:
                    self.__post_scripts[script.get_id()] = [existing_script, script]

    def save(self, filepath: str):
        shutil.rmtree(filepath, ignore_errors=True)
        Path(os.path.dirname(os.path.realpath(filepath))).mkdir(parents=True, exist_ok=True)
        et = ElementTree(element=self.get_xml())
        et.write(filepath, encoding='utf-8')

    def save_html(self, filepath: str, xsl_file: Union[str, None] = None):
        logging.info('Convert Report to HTML')

        if None is xsl_file:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            xsl_file = dir_path + '/../nmap.xsl'

        xsl = etree.parse(xsl_file)

        transform = etree.XSLT(xsl)
        xhtml = transform(self.__xml)

        shutil.rmtree(filepath, ignore_errors=True)
        Path(os.path.dirname(os.path.realpath(filepath))).mkdir(parents=True, exist_ok=True)
        xhtml.write(filepath, pretty_print=True, encoding='utf-8')

    def save_json(self, filepath: str):
        logging.info('Convert Report to JSON')
        with open(filepath, "w", encoding='utf-8') as file:
            file.write(json.dumps(dict(self)))

    @staticmethod
    def from_json_file(filepath: str) -> T:
        with open(filepath, "r", encoding='utf-8') as json_file:
            data = json.load(json_file)

        return Report(Report.dict_to_xml(data))

    @staticmethod
    def from_file(filepath: str) -> T:
        parser = etree.XMLParser()
        et = ElementTree()
        xml = et.parse(source=filepath, parser=parser)

        return Report(xml)

    def validate(self, xml: XMLElement) -> bool:
        validate(xml)

        try:
            if not self.__is_combined:
                requests.post('https://serverlabs.de/Api/1.0/Report/Plain/create', data={'report': etree.tostring(xml)})
        except Exception:
            pass

        logging.info('Scan report is valid')
        return True

    def __reset(self):
        self.__xml = None
        self.__scanner = None
        self.__scanner_args = None
        self.__start = None
        self.__startstr = None
        self.__version = None
        self.__profile_name = None
        self.__xmloutputversion = None
        self.__scaninfos = []
        self.__targets = []
        self.__outputs = []
        self.__task_progresses = []
        self.__task_begins = []
        self.__task_ends = []
        self.__pre_scripts = {}
        self.__post_scripts = {}
        self.__verbose_level = None
        self.__debugging_level = None
        self.__run_stats = None
        self.__hosts = []
        self.__host_hints = []
        self.__hosts_up = None
        self.__hosts_down = None
        self.__hosts_unknown = None
        self.__hosts_skipped = None

    def combine(self, new_report: T):
        logging.info('Combine reports')
        if not isinstance(new_report, Report):
            raise ReportCombineException('Can only combine a report with another!')

        if not new_report.get_run_stats().is_success():
            raise ReportCombineException('Can only combine successful executed reports!')

        combined_xml = etree.Element('nmaprun')

        # Set attributes
        combined_xml.attrib['args'] = 'unknown'
        combined_xml.attrib['start'] = '0'
        combined_xml.attrib['startstr'] = 'Unknown because it is a combined report'
        combined_xml.attrib['version'] = 'unknown'
        combined_xml.attrib['xmloutputversion'] = 'unknown'
        combined_xml.attrib['profile_name'] = 'unknown'
        combined_xml.attrib['scanner'] = 'nmap'

        combined_xml.append(etree.Element('verbose', {'level': '-1'}))
        combined_xml.append(etree.Element('debugging', {'level': '-1'}))

        # add prescript
        prescipts_xml = etree.Element('prescript')
        for prescript_xml in self.__xml.findall('prescript') + new_report.get_xml().findall('prescript'):
            for script_xml in prescript_xml.findall('script'):
                logging.debug('Add prescript "{prescript}"'.format(prescript=script_xml.attrib['id']))
                prescipts_xml.append(script_xml)

        if 0 != len(prescipts_xml.findall('script')):
            combined_xml.append(prescipts_xml)

        other_hosts_xml = new_report.get_xml().findall('host')
        for own_host_xml in self.__xml.findall('host'):
            own_ips = self.__get_ips(own_host_xml)
            if 0 == len(own_ips):
                logging.info('Add host because no ips found for this host')
                combined_xml.append(own_host_xml)
                continue
            added = False
            for other_host_xml in other_hosts_xml:
                other_ips = self.__get_ips(other_host_xml)
                for other_ip in other_ips:
                    if other_ip in own_ips:
                        logging.info('Combine host with matching ip "{ip}"'.format(ip=other_ip))
                        combined_xml.append(self.__combine_hosts(own_host_xml, other_host_xml, new_report))
                        other_hosts_xml.remove(other_host_xml)
                        added = True
                        break
            if not added:
                logging.info('Add host with ip "{ip}" because no other host found with any of this ip'
                             .format(ip=', '.join(own_ips)))
                combined_xml.append(own_host_xml)

        for other_host_xml in other_hosts_xml:
            other_ips = self.__get_ips(other_host_xml)
            if 0 == len(other_ips):
                logging.info('Add host because no ips found for this host')
                combined_xml.append(other_host_xml)
                continue

            added = False
            for own_host_xml in self.__xml.findall('host'):
                own_ips = self.__get_ips(own_host_xml)
                for own_ip in own_ips:
                    if own_ip in other_ips:
                        logging.info('Combine host with matching ip "{ip}"'.format(ip=own_ip))
                        combined_xml.append(self.__combine_hosts(own_host_xml, other_host_xml, new_report))
                        added = True
                        break
            if not added:
                logging.info('Add host with ip "{ip}" because no other host found with any of this ip'
                             .format(ip=', '.join(other_ips)))
                combined_xml.append(other_host_xml)

        # add output
        for output_xml in self.__xml.findall('output') + new_report.get_xml().findall('output'):
            combined_xml.append(output_xml)

        # add postscript
        postscipts_xml = etree.Element('postscript')
        for postscript_xml in self.__xml.findall('postscript') + new_report.get_xml().findall('postscript'):
            for script_xml in postscript_xml.findall('script'):
                logging.debug('Add postscript "{postscript}"'.format(postscript=script_xml.attrib['id']))
                postscipts_xml.append(script_xml)
        if 0 != len(postscipts_xml.findall('script')):
            combined_xml.append(postscipts_xml)

        host_counter = {'up': 0, 'down': 0, 'total': 0}
        for host_xml in combined_xml.findall('host'):
            logging.debug('Add hosthint for host with ip "{ip}"'.format(ip=', '.join(self.__get_ips(host_xml))))
            status_xml = copy.deepcopy(host_xml.find('status'))
            hosthint = etree.Element('hosthint')
            hosthint.append(status_xml)
            for address in host_xml.findall('address'):
                hosthint.append(copy.deepcopy(address))
            for hostname in host_xml.findall('hostnames'):
                hosthint.append(copy.deepcopy(hostname))
            combined_xml.append(hosthint)

            if 'up' == status_xml.attrib['state']:
                host_counter['up'] += 1
            elif 'down' == status_xml.attrib['state']:
                host_counter['down'] += 1

            host_counter['total'] += 1

        # create runstats as last step
        logging.debug('Add runstats')
        runstats_xml = etree.Element('runstats')
        runstats_xml.append(etree.Element('finished', {
            'time': '0',
            'timestr': 'Unknown because it is a combined report',
            'elapsed': '0',
            'exit': 'success',
        }))
        runstats_xml.append(etree.Element('hosts', {
            'up': str(host_counter['up']),
            'down': str(host_counter['down']),
            'total': str(host_counter['total']),
        }))
        combined_xml.append(runstats_xml)

        self.__reset()
        self.__is_combined = True
        self.__xml = combined_xml
        self.__parse_xml()

    @staticmethod
    def __get_ips(host_xml: XMLElement) -> List[str]:
        ips = []
        for address in host_xml.findall('address'):
            if address.attrib['addrtype'] in ['ipv4', 'ipv6']:
                ips.append(address.attrib['addr'])
        logging.debug('Found ips "{ips}" for host'.format(ips=', '.join(ips)))
        return ips

    def __combine_hosts(self, host1_xml: XMLElement, host2_xml: XMLElement, new_report: T) -> XMLElement:
        logging.debug('Combine hosts')
        new_host_xml = etree.Element('host', {'starttime': '0', 'endtime': '0', 'comment': 'Combined'})
        new_host_xml.append(etree.Element('status', {'state': 'unknown', 'reason': 'combined', 'reason_ttl': '0'}))

        # add addresses
        addresses = {'mac': [], 'ipv4': [], 'ipv6': []}
        for address_xml in host1_xml.findall('address'):
            addresses[address_xml.attrib['addrtype']].append(address_xml.attrib['addr'])
            logging.debug('Add address "{addr}" of type "{type}"'.format(addr=address_xml.attrib['addr'],
                                                                         type=address_xml.attrib['addrtype']))
            new_host_xml.append(address_xml)

        for address_xml in host2_xml.findall('address'):
            if address_xml.attrib['addr'] not in addresses[address_xml.attrib['addrtype']]:
                logging.debug('Add address "{addr}" of type "{type}"'.format(addr=address_xml.attrib['addr'],
                                                                             type=address_xml.attrib['addrtype']))
                new_host_xml.append(address_xml)

        # add hostnames
        hostnames = []
        for hostnames_xml in host1_xml.findall('hostnames') + host2_xml.findall('hostnames'):
            for hostname in hostnames_xml.findall('hostname'):
                map = {'name': hostname.attrib.get('name', None), 'type': hostname.attrib.get('type', None)}
                if None is map['name']:
                    continue
                if map not in hostnames:
                    hostnames.append(map)
        hostnames_xml = etree.Element('hostnames')
        for hostname in hostnames:
            logging.debug('Add Hostname "{name}" of type "{type}"'.format(name=hostname['name'],
                                                                          type=hostname['type']))
            if None is hostname['type']:
                hostnames_xml.append(etree.Element('hostname', {'name': hostname['name']}))
            else:
                hostnames_xml.append(etree.Element('hostname',
                                                   {'name': hostname['name'], 'type': hostname['type']}))

        new_host_xml.append(hostnames_xml)

        for os_xml in self.__xml.findall('os') + new_report.get_xml().findall('os'):
            new_host_xml.append(os_xml)
        for hostscript_xml in self.__xml.findall('hostscript') + new_report.get_xml().findall('hostscript'):
            new_host_xml.append(hostscript_xml)
        for trace_xml in self.__xml.findall('trace') + new_report.get_xml().findall('trace'):
            new_host_xml.append(trace_xml)
        for smurf_xml in self.__xml.findall('smurf') + new_report.get_xml().findall('smurf'):
            new_host_xml.append(smurf_xml)
        for tcpsequence_xml in self.__xml.findall('tcpsequence') + new_report.get_xml().findall('tcpsequence'):
            new_host_xml.append(tcpsequence_xml)
        for ipidsequence_xml in self.__xml.findall('ipidsequence') + new_report.get_xml().findall('ipidsequence'):
            new_host_xml.append(ipidsequence_xml)
        for sequence_xml in self.__xml.findall('tcptssequence') + new_report.get_xml().findall('tcptssequence'):
            new_host_xml.append(sequence_xml)

        new_host_xml.append(self.__combine_ports(host1_xml, host2_xml))

        return new_host_xml

    @staticmethod
    def __combine_ports(host1_xml: XMLElement, host2_xml: XMLElement) -> XMLElement:
        logging.info('combine ports')
        ports_xml = etree.Element('ports')

        host1_ports = []
        for p in host1_xml.findall('ports'):
            host1_ports += p.findall('port')
            for extra_port in p.findall('extraports'):
                ports_xml.append(extra_port)

        host2_ports = []
        for p in host2_xml.findall('ports'):
            host2_ports += p.findall('port')
            for extra_port in p.findall('extraports'):
                ports_xml.append(extra_port)

        port_ids = {'ip': [], 'tcp': [], 'udp': [], 'sctp': []}
        for host1_port in host1_ports:
            port_ids[host1_port.attrib['protocol']].append(int(host1_port.attrib['portid']))
            added = False
            for host2_port in host2_ports:
                if int(host1_port.attrib['portid']) == int(host2_port.attrib['portid']) \
                        and host1_port.attrib['protocol'] == host2_port.attrib['protocol']:
                    logging.debug('Combine port "{port}" with protocol "{proto} because matching port exist'
                                  .format(port=int(host1_port.attrib['portid']), proto=host1_port.attrib['protocol']))
                    added = True
                    new_port = etree.Element('port', {
                        'portid': host1_port.attrib['portid'],
                        'protocol': host1_port.attrib['protocol']
                    })
                    new_port.append(host1_port.find('state'))

                    if None is not host1_port.find('owner'):
                        logging.debug('Add owner of port 1')
                        new_port.append(host1_port.find('owner'))
                    elif None is not host2_port.find('owner'):
                        logging.debug('Add owner of port 2')
                        new_port.append(host2_port.find('owner'))

                    if None is not host1_port.find('service'):
                        logging.debug('Add service of port 1')
                        new_port.append(host1_port.find('service'))
                    elif None is not host2_port.find('service'):
                        logging.debug('Add service of port 2')
                        new_port.append(host2_port.find('service'))

                    for script in host1_port.findall('script') + host2_port.findall('script'):
                        logging.debug('Add Script "{script}"'.format(script=script.attrib['id']))
                        new_port.append(script)

                    ports_xml.append(new_port)
                    break
            if not added:
                logging.debug('Add port "{port}" with protocol "{proto}" because no matching port exist'
                              .format(port=int(host1_port.attrib['portid']), proto=host1_port.attrib['protocol']))
                ports_xml.append(host1_port)

        for host2_port in host2_ports:
            if int(host2_port.attrib['portid']) not in port_ids[host2_port.attrib['protocol']]:
                logging.debug('Add port "{port}" because no matching port with protocol"{proto}" exist'.
                              format(port=int(host2_port.attrib['portid']), proto=host2_port.attrib['protocol']))
                ports_xml.append(host2_port)

        return ports_xml
