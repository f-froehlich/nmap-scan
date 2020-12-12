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
from threading import Thread

from nmap_scan.Host.Host import Host
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Stats.Output import Output
from nmap_scan.Stats.RunStats import RunStats
from nmap_scan.Stats.ScanInfo import ScanInfo
from nmap_scan.Stats.Target import Target
from nmap_scan.Stats.TaskBegin import TaskBegin
from nmap_scan.Stats.TaskEnd import TaskEnd
from nmap_scan.Stats.TaskProgress import TaskProgress


class Report:

    def __init__(self, xml):
        self.__xml = xml
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
        self.__hosts_up = None
        self.__hosts_down = None
        self.__hosts_unknown = None
        self.__hosts_skipped = None

        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_scanner(self):
        return self.__scanner

    def get_scannder_args(self):
        return self.__scanner_args

    def get_start(self):
        return self.__start

    def get_start_string(self):
        return self.__startstr

    def get_version(self):
        return self.__version

    def get_xml_output_version(self):
        return self.__xmloutputversion

    def get_profile_name(self):
        return self.__profile_name

    def get_scaninfos(self):
        return self.__scaninfos

    def get_verbose_level(self):
        return self.__verbose_level

    def get_debugging_level(self):
        return self.__debugging_level

    def get_targets(self):
        return self.__targets

    def get_outputs(self):
        return self.__outputs

    def get_task_progresses(self):
        return self.__task_progresses

    def get_task_begins(self):
        return self.__task_begins

    def get_task_ends(self):
        return self.__task_ends

    def get_run_stats(self):
        return self.__run_stats

    def get_hosts(self):
        return self.__hosts

    def get_hosts_up(self):
        if None == self.__hosts_up:
            self.__hosts_up = [h for h in self.__hosts_up if h.is_up()]
        return self.__hosts_up

    def get_hosts_down(self):
        if None == self.__hosts_down:
            self.__hosts_down = [h for h in self.__hosts_down if h.is_down()]
        return self.__hosts_down

    def get_hosts_unknown(self):
        if None == self.__hosts_unknown:
            self.__hosts_unknown = [h for h in self.__hosts_unknown if h.is_unknown()]
        return self.__hosts_unknown

    def get_hosts_skipped(self):
        if None == self.__hosts_skipped:
            self.__hosts_skipped = [h for h in self.__hosts_skipped if h.is_skipped()]
        return self.__hosts_skipped

    def get_pre_scripts(self):
        return self.__pre_scripts

    def has_pre_script(self, pre_script_id):
        return None != self.__pre_scripts.get(pre_script_id, None)

    def get_pre_script(self, pre_script_id):
        return self.__pre_scripts.get(pre_script_id, None)

    def get_post_scripts(self):
        return self.__post_scripts

    def has_post_script(self, post_script_id):
        return None != self.__post_scripts.get(post_script_id, None)

    def get_post_script(self, post_script_id):
        return self.__post_scripts.get(post_script_id, None)

    def get_host_with_port(self, port_id):
        return self.get_hosts_with_port([port_id])

    def get_hosts_with_port(self, port_ids):
        def callback(port):
            return True

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port(self, port_ids):
        def callback(port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port(self, port_ids):
        def callback(port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port(self, port_ids):
        def callback(port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port(self, port_ids):
        def callback(port):
            return True

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_open(self, port_ids):
        def callback(port):
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_open(self, port_ids):
        def callback(port):
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_open(self, port_ids):
        def callback(port):
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_open(self, port_ids):
        def callback(port):
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_open(self, port_ids):
        def callback(port):
            return port.is_open()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_closed(self, port_ids):
        def callback(port):
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_closed(self, port_ids):
        def callback(port):
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_closed(self, port_ids):
        def callback(port):
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_closed(self, port_ids):
        def callback(port):
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_closed(self, port_ids):
        def callback(port):
            return port.is_closed()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_filtered(self, port_ids):
        def callback(port):
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_filtered(self, port_ids):
        def callback(port):
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_filtered(self, port_ids):
        def callback(port):
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_filtered(self, port_ids):
        def callback(port):
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_filtered(self, port_ids):
        def callback(port):
            return port.is_filtered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def get_hosts_with_port_unfiltered(self, port_ids):
        def callback(port):
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.__hosts, callback)

    def get_hosts_up_with_port_unfiltered(self, port_ids):
        def callback(port):
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_up(), callback)

    def get_hosts_down_with_port_unfiltered(self, port_ids):
        def callback(port):
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_down(), callback)

    def get_hosts_unknown_with_port_unfiltered(self, port_ids):
        def callback(port):
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_unknown(), callback)

    def get_hosts_skipped_with_port_unfiltered(self, port_ids):
        def callback(port):
            return port.is_unfiltered()

        return self.__get_hosts_with_port(port_ids, self.get_hosts_skipped(), callback)

    def __get_hosts_with_port(self, port_ids, search_hosts, callback):
        hosts = []
        for host in search_hosts:
            if host in hosts:
                continue

            for port_id in port_ids:
                if host.has_port(port_id) and callback(host.get_port(port_id)):
                    hosts.append(host)
                    break

        return hosts

    def get_hosts_with_script(self, script_id):
        hosts = []
        for host in self.__hosts:
            if host in hosts:
                continue
            host_ports = []
            for port in host.get_ports():
                if port.has_script(script_id):
                    host_ports.append(port)
            if 0 != len(host_ports):
                hosts.append({'host': host, 'ports': host_ports})

        return hosts

    def __parse_xml(self):
        nmaprun = self.get_xml().attrib
        self.__scanner = nmaprun['scanner']
        self.__scanner_args = nmaprun.get('args', None)
        self.__start = int(nmaprun['start']) if None != nmaprun.get('start', None) else None
        self.__startstr = nmaprun.get('startstr', None)
        self.__version = nmaprun['version']
        self.__xmloutputversion = nmaprun.get('xmloutputversion', None)
        self.__profile_name = nmaprun.get('profile_name', None)

        hosts_xml = self.get_xml().findall('host')
        hosts_xml_len = len(hosts_xml)
        self.__hosts = [None] * hosts_xml_len
        threads = [None] * hosts_xml_len
        thread_id = 0
        for host_xml in hosts_xml:
            logging.debug('Start thread with id "{id}"'.format(id=thread_id))
            threads[thread_id] = Thread(target=self.__parse_host_xml, args=(host_xml, thread_id))
            threads[thread_id].start()
            thread_id += 1

        verbose_xml = self.get_xml().find('verbose')
        if None != verbose_xml:
            self.__verbose_level = int(verbose_xml.attrib['level']) if None != verbose_xml.attrib.get('level') else None

        debugging_xml = self.get_xml().find('debugging')
        if None != debugging_xml:
            self.__debugging_level = int(debugging_xml.attrib['level']) if None != debugging_xml.attrib.get(
                'level') else None

        run_stats_xml = self.get_xml().find('runstats')
        if None != run_stats_xml:
            self.__run_stats = RunStats(run_stats_xml)

        for scaninfo_xml in self.get_xml().findall('scaninfo'):
            self.__scaninfos.append(ScanInfo(scaninfo_xml))

        for target_xml in self.__xml.findall('target'):
            self.__targets.append(Target(target_xml))

        for output_xml in self.__xml.findall('output'):
            self.__outputs.append(Output(output_xml))

        for task_progress_xml in self.__xml.findall('taskprogress'):
            self.__task_progresses.append(TaskProgress(task_progress_xml))

        for task_begin_xml in self.__xml.findall('taskbegin'):
            self.__task_begins.append(TaskBegin(task_begin_xml))

        for task_end_xml in self.__xml.findall('taskend'):
            self.__task_ends.append(TaskEnd(task_end_xml))

        for prescript_xml in self.__xml.findall('prescript'):
            for script_xml in prescript_xml.findall('script'):
                script = parse(script_xml)
                existing_script = self.__pre_scripts.get(script.get_id(), None)
                if None == existing_script:
                    self.__pre_scripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__pre_scripts[script.get_id()].append(script)
                else:
                    self.__pre_scripts[script.get_id()] = [existing_script, script]

        for postscript_xml in self.__xml.findall('postscript'):
            for script_xml in postscript_xml.findall('script'):
                script = parse(script_xml)
                existing_script = self.__post_scripts.get(script.get_id(), None)
                if None == existing_script:
                    self.__post_scripts[script.get_id()] = script
                elif isinstance(existing_script, list):
                    self.__post_scripts[script.get_id()].append(script)
                else:
                    self.__post_scripts[script.get_id()] = [existing_script, script]

        for thread in threads:
            thread.join()

    def __parse_host_xml(self, host_xml, thread_id):
        self.__hosts[thread_id] = Host(host_xml)
        logging.debug('Thread with id "{id}" ended'.format(id=thread_id))
