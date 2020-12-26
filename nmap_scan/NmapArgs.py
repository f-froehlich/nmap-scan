#!/usr/bin/python3
# -*- coding: utf-8

import argparse

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
from nmap_scan.Exceptions.LogicException import LogicException


class NmapArgs:

    def __init__(self, hosts=[], num_hosts=None, exclude_hosts=[], dns_servers=[], system_dns=False, traceroute=False,
                 ports=[], exclude_ports=[], fast_mode=False, scan_consecutively=False, top_ports=None, port_ratio=None,
                 service_discovery=False, version_intensity=None, version_light=None, version_all=False,
                 version_trace=False, default_script=False, scripts=[], script_args=[], script_trace=False,
                 os_detection=False, os_guess=False, os_scan_limit=None, timing=None, min_hostgroup=None,
                 max_hostgroup=None, min_parallelism=None, max_parallelism=None, min_rtt_timeout=None,
                 max_rtt_timeout=None, initial_rtt_timeout=None, max_retries=None, host_timeout=None, scan_delay=None,
                 max_scan_delay=None, min_rate=None, max_rate=None, ipv6_scan=False, privileged=False,
                 unprivileged=False, send_eth=False, send_ip=False, datadir=None, misc_a=False, mtu=None, decoys=[],
                 spoof_ip=None, interface=None, source_port=None, proxies=[], data=None, data_string=None,
                 data_length=None, ip_options=None, ttl=None, spoof_mac=None, bad_sum=False, never_dns_resolution=False,
                 always_dns_resolution=False, pn=False
                 ):
        self.__argpaser = None
        self.__locked = False

        self.__always_dns_resolution = always_dns_resolution
        self.__never_dns_resolution = never_dns_resolution
        self.__port_ratio = port_ratio
        self.__top_ports = top_ports
        self.__scan_consecutively = scan_consecutively
        self.__fast_mode = fast_mode
        self.__exclude_ports = exclude_ports
        self.__version_all = version_all
        self.__script_trace = script_trace
        self.__version_light = version_light
        self.__version_intensity = version_intensity
        self.__service_discovery = service_discovery
        self.__pn = pn
        self.__script_args = script_args
        self.__scripts = scripts
        self.__default_script = default_script
        self.__version_trace = version_trace
        self.__min_hostgroup = min_hostgroup
        self.__timing = timing
        self.__os_scan_limit = os_scan_limit
        self.__os_guess = os_guess
        self.__os_detection = os_detection
        self.__min_rtt_timeout = min_rtt_timeout
        self.__max_parallelism = max_parallelism
        self.__min_parallelism = min_parallelism
        self.__max_hostgroup = max_hostgroup
        self.__scan_delay = scan_delay
        self.__host_timeout = host_timeout
        self.__max_retries = max_retries
        self.__initial_rtt_timeout = initial_rtt_timeout
        self.__privileged = privileged
        self.__max_rtt_timeout = max_rtt_timeout
        self.__decoys = decoys
        self.__mtu = mtu
        self.__misc_a = misc_a
        self.__datadir = datadir
        self.__ipv6_scan = ipv6_scan
        self.__max_rate = max_rate
        self.__min_rate = min_rate
        self.__data_string = data_string
        self.__data = data
        self.__proxies = proxies
        self.__source_port = source_port
        self.__send_ip = send_ip
        self.__unprivileged = unprivileged
        self.__send_eth = send_eth
        self.__max_scan_delay = max_scan_delay
        self.__interface = interface
        self.__spoof_ip = spoof_ip
        self.__bad_sum = bad_sum
        self.__spoof_mac = spoof_mac
        self.__ttl = ttl
        self.__ip_options = ip_options
        self.__data_length = data_length
        self.__ports = ports
        self.__traceroute = traceroute
        self.__system_dns = system_dns
        self.__dns_servers = dns_servers
        self.__exclude_hosts = exclude_hosts
        self.__num_hosts = num_hosts
        self.__hosts = hosts

    def lock(self):
        self.__locked = True

    def is_locked(self):
        return self.__locked

    def set_always_dns_resolution(self, always_dns_resolution):
        if not self.__locked:
            self.__always_dns_resolution = always_dns_resolution

        return self

    def get_always_dns_resolution(self):
        return self.__always_dns_resolution

    def set_never_dns_resolution(self, never_dns_resolution):
        if not self.__locked:
            self.__never_dns_resolution = never_dns_resolution

        return self

    def get_never_dns_resolution(self):
        return self.__never_dns_resolution

    def set_port_ratio(self, port_ratio):
        if not self.__locked:
            self.__port_ratio = port_ratio

        return self

    def get_port_ratio(self):
        return self.__port_ratio

    def set_top_ports(self, top_ports):
        if not self.__locked:
            self.__top_ports = top_ports

        return self

    def get_top_ports(self):
        return self.__top_ports

    def set_scan_consecutively(self, scan_consecutively):
        if not self.__locked:
            self.__scan_consecutively = scan_consecutively

        return self

    def get_scan_consecutively(self):
        return self.__scan_consecutively

    def set_fast_mode(self, fast_mode):
        if not self.__locked:
            self.__fast_mode = fast_mode

        return self

    def get_fast_mode(self):
        return self.__fast_mode

    def set_exclude_ports(self, exclude_ports):
        if not self.__locked:
            self.__exclude_ports = exclude_ports

        return self

    def get_exclude_ports(self):
        return self.__exclude_ports

    def set_version_all(self, version_all):
        if not self.__locked:
            self.__version_all = version_all

        return self

    def get_version_all(self):
        return self.__version_all

    def set_script_trace(self, script_trace):
        if not self.__locked:
            self.__script_trace = script_trace

        return self

    def get_script_trace(self):
        return self.__script_trace

    def set_version_light(self, version_light):
        if not self.__locked:
            self.__version_light = version_light

        return self

    def get_version_light(self):
        return self.__version_light

    def set_version_intensity(self, version_intensity):
        if not self.__locked:
            self.__version_intensity = version_intensity

        return self

    def get_version_intensity(self):
        return self.__version_intensity

    def set_service_discovery(self, service_discovery):
        if not self.__locked:
            self.__service_discovery = service_discovery

        return self

    def get_service_discovery(self):
        return self.__service_discovery

    def set_pn(self, pn):
        if not self.__locked:
            self.__pn = pn

        return self

    def get_pn(self):
        return self.__pn

    def set_script_args(self, script_args):
        if not self.__locked:
            self.__script_args = script_args

        return self

    def get_script_args(self):
        return self.__script_args

    def set_scripts(self, scripts):
        if not self.__locked:
            self.__scripts = scripts

        return self

    def get_scripts(self):
        return self.__scripts

    def set_default_script(self, default_script):
        if not self.__locked:
            self.__default_script = default_script

        return self

    def get_default_script(self):
        return self.__default_script

    def set_version_trace(self, version_trace):
        if not self.__locked:
            self.__version_trace = version_trace

        return self

    def get_version_trace(self):
        return self.__version_trace

    def set_min_hostgroup(self, min_hostgroup):
        if not self.__locked:
            self.__min_hostgroup = min_hostgroup

        return self

    def get_min_hostgroup(self):
        return self.__min_hostgroup

    def set_timing(self, timing):
        if not self.__locked:
            self.__timing = timing

        return self

    def get_timing(self):
        return self.__timing

    def set_os_scan_limit(self, os_scan_limit):
        if not self.__locked:
            self.__os_scan_limit = os_scan_limit

        return self

    def get_os_scan_limit(self):
        return self.__os_scan_limit

    def set_os_guess(self, os_guess):
        if not self.__locked:
            self.__os_guess = os_guess

        return self

    def get_os_guess(self):
        return self.__os_guess

    def set_os_detection(self, os_detection):
        if not self.__locked:
            self.__os_detection = os_detection

        return self

    def get_os_detection(self):
        return self.__os_detection

    def set_min_rtt_timeout(self, min_rtt_timeout):
        if not self.__locked:
            self.__min_rtt_timeout = min_rtt_timeout

        return self

    def get_min_rtt_timeout(self):
        return self.__min_rtt_timeout

    def set_max_parallelism(self, max_parallelism):
        if not self.__locked:
            self.__max_parallelism = max_parallelism

        return self

    def get_max_parallelism(self):
        return self.__max_parallelism

    def set_min_parallelism(self, min_parallelism):
        if not self.__locked:
            self.__min_parallelism = min_parallelism

        return self

    def get_min_parallelism(self):
        return self.__min_parallelism

    def set_max_hostgroup(self, max_hostgroup):
        if not self.__locked:
            self.__max_hostgroup = max_hostgroup

        return self

    def get_max_hostgroup(self):
        return self.__max_hostgroup

    def set_scan_delay(self, scan_delay):
        if not self.__locked:
            self.__scan_delay = scan_delay

        return self

    def get_scan_delay(self):
        return self.__scan_delay

    def set_host_timeout(self, host_timeout):
        if not self.__locked:
            self.__host_timeout = host_timeout

        return self

    def get_host_timeout(self):
        return self.__host_timeout

    def set_max_retries(self, max_retries):
        if not self.__locked:
            self.__max_retries = max_retries

        return self

    def get_max_retries(self):
        return self.__max_retries

    def set_initial_rtt_timeout(self, initial_rtt_timeout):
        if not self.__locked:
            self.__initial_rtt_timeout = initial_rtt_timeout

        return self

    def get_initial_rtt_timeout(self):
        return self.__initial_rtt_timeout

    def set_privileged(self, privileged):
        if not self.__locked:
            self.__privileged = privileged

        return self

    def get_privileged(self):
        return self.__privileged

    def set_max_rtt_timeout(self, max_rtt_timeout):
        if not self.__locked:
            self.__max_rtt_timeout = max_rtt_timeout

        return self

    def get_max_rtt_timeout(self):
        return self.__max_rtt_timeout

    def set_decoys(self, decoys):
        if not self.__locked:
            self.__decoys = decoys

        return self

    def get_decoys(self):
        return self.__decoys

    def set_mtu(self, mtu):
        if not self.__locked:
            self.__mtu = mtu

        return self

    def get_mtu(self):
        return self.__mtu

    def set_misc_a(self, misc_a):
        if not self.__locked:
            self.__misc_a = misc_a

        return self

    def get_misc_a(self):
        return self.__misc_a

    def set_datadir(self, datadir):
        if not self.__locked:
            self.__datadir = datadir

        return self

    def get_datadir(self):
        return self.__datadir

    def set_ipv6_scan(self, ipv6_scan):
        if not self.__locked:
            self.__ipv6_scan = ipv6_scan

        return self

    def get_ipv6_scan(self):
        return self.__ipv6_scan

    def set_max_rate(self, max_rate):
        if not self.__locked:
            self.__max_rate = max_rate

        return self

    def get_max_rate(self):
        return self.__max_rate

    def set_min_rate(self, min_rate):
        if not self.__locked:
            self.__min_rate = min_rate

        return self

    def get_min_rate(self):
        return self.__min_rate

    def set_data_string(self, data_string):
        if not self.__locked:
            self.__data_string = data_string

        return self

    def get_data_string(self):
        return self.__data_string

    def set_data(self, data):
        if not self.__locked:
            self.__data = data

        return self

    def get_data(self):
        return self.__data

    def set_proxies(self, proxies):
        if not self.__locked:
            self.__proxies = proxies

        return self

    def get_proxies(self):
        return self.__proxies

    def set_source_port(self, source_port):
        if not self.__locked:
            self.__source_port = source_port

        return self

    def get_source_port(self):
        return self.__source_port

    def set_send_ip(self, send_ip):
        if not self.__locked:
            self.__send_ip = send_ip

        return self

    def get_send_ip(self):
        return self.__send_ip

    def set_unprivileged(self, unprivileged):
        if not self.__locked:
            self.__unprivileged = unprivileged

        return self

    def get_unprivileged(self):
        return self.__unprivileged

    def set_send_eth(self, send_eth):
        if not self.__locked:
            self.__send_eth = send_eth

        return self

    def get_send_eth(self):
        return self.__send_eth

    def set_max_scan_delay(self, max_scan_delay):
        if not self.__locked:
            self.__max_scan_delay = max_scan_delay

        return self

    def get_max_scan_delay(self):
        return self.__max_scan_delay

    def set_interface(self, interface):
        if not self.__locked:
            self.__interface = interface

        return self

    def get_interface(self):
        return self.__interface

    def set_spoof_ip(self, spoof_ip):
        if not self.__locked:
            self.__spoof_ip = spoof_ip

        return self

    def get_spoof_ip(self):
        return self.__spoof_ip

    def set_bad_sum(self, bad_sum):
        if not self.__locked:
            self.__bad_sum = bad_sum

        return self

    def get_bad_sum(self):
        return self.__bad_sum

    def set_spoof_mac(self, spoof_mac):
        if not self.__locked:
            self.__spoof_mac = spoof_mac

        return self

    def get_spoof_mac(self):
        return self.__spoof_mac

    def set_ttl(self, ttl):
        if not self.__locked:
            self.__ttl = ttl

        return self

    def get_ttl(self):
        return self.__ttl

    def set_ip_options(self, ip_options):
        if not self.__locked:
            self.__ip_options = ip_options

        return self

    def get_ip_options(self):
        return self.__ip_options

    def set_data_length(self, data_length):
        if not self.__locked:
            self.__data_length = data_length

        return self

    def get_data_length(self):
        return self.__data_length

    def set_ports(self, ports):
        if not self.__locked:
            self.__ports = ports

        return self

    def get_ports(self):
        return self.__ports

    def set_traceroute(self, traceroute):
        if not self.__locked:
            self.__traceroute = traceroute

        return self

    def get_traceroute(self):
        return self.__traceroute

    def set_system_dns(self, system_dns):
        if not self.__locked:
            self.__system_dns = system_dns

        return self

    def get_system_dns(self):
        return self.__system_dns

    def set_dns_servers(self, dns_servers):
        if not self.__locked:
            self.__dns_servers = dns_servers

        return self

    def get_dns_servers(self):
        return self.__dns_servers

    def set_exclude_hosts(self, exclude_hosts):
        if not self.__locked:
            self.__exclude_hosts = exclude_hosts

        return self

    def get_exclude_hosts(self):
        return self.__exclude_hosts

    def set_num_hosts(self, num_hosts):
        if not self.__locked:
            self.__num_hosts = num_hosts

        return self

    def get_num_hosts(self):
        return self.__num_hosts

    def set_hosts(self, hosts):
        if not self.__locked:
            self.__hosts = hosts

        return self

    def get_hosts(self):
        return self.__hosts

    def clone(self):
        return NmapArgs(
            always_dns_resolution=self.__always_dns_resolution,
            never_dns_resolution=self.__never_dns_resolution,
            port_ratio=self.__port_ratio,
            top_ports=self.__top_ports,
            scan_consecutively=self.__scan_consecutively,
            fast_mode=self.__fast_mode,
            exclude_ports=self.__exclude_ports,
            version_all=self.__version_all,
            script_trace=self.__script_trace,
            version_light=self.__version_light,
            version_intensity=self.__version_intensity,
            service_discovery=self.__service_discovery,
            pn=self.__pn,
            script_args=self.__script_args,
            scripts=self.__scripts,
            default_script=self.__default_script,
            version_trace=self.__version_trace,
            min_hostgroup=self.__min_hostgroup,
            timing=self.__timing,
            os_scan_limit=self.__os_scan_limit,
            os_guess=self.__os_guess,
            os_detection=self.__os_detection,
            min_rtt_timeout=self.__min_rtt_timeout,
            max_parallelism=self.__max_parallelism,
            min_parallelism=self.__min_parallelism,
            max_hostgroup=self.__max_hostgroup,
            scan_delay=self.__scan_delay,
            host_timeout=self.__host_timeout,
            max_retries=self.__max_retries,
            initial_rtt_timeout=self.__initial_rtt_timeout,
            privileged=self.__privileged,
            max_rtt_timeout=self.__max_rtt_timeout,
            decoys=self.__decoys,
            mtu=self.__mtu,
            misc_a=self.__misc_a,
            datadir=self.__datadir,
            ipv6_scan=self.__ipv6_scan,
            max_rate=self.__max_rate,
            min_rate=self.__min_rate,
            data_string=self.__data_string,
            data=self.__data,
            proxies=self.__proxies,
            source_port=self.__source_port,
            send_ip=self.__send_ip,
            unprivileged=self.__unprivileged,
            send_eth=self.__send_eth,
            max_scan_delay=self.__max_scan_delay,
            interface=self.__interface,
            spoof_ip=self.__spoof_ip,
            bad_sum=self.__bad_sum,
            spoof_mac=self.__spoof_mac,
            ttl=self.__ttl,
            ip_options=self.__ip_options,
            data_length=self.__data_length,
            ports=self.__ports,
            traceroute=self.__traceroute,
            system_dns=self.__system_dns,
            dns_servers=self.__dns_servers,
            exclude_hosts=self.__exclude_hosts,
            num_hosts=self.__num_hosts,
            hosts=self.__hosts
        )

    def get_arg_list(self):
        self.__locked = True
        args = ['-oX', '-']

        if 0 != len(self.__exclude_hosts):
            args.append('--exclude')
            args.append(','.join(self.__exclude_hosts))

        if 0 != len(self.__dns_servers):
            args.append('--dns-servers')
            args.append(','.join(self.__dns_servers))

        for script in self.__scripts:
            args.append('--script')
            args.append(script)

        if 0 != len(self.__script_args):
            args.append('--script-args=' + ','.join(self.__script_args))

        if 0 != len(self.__proxies):
            args.append('--proxies')
            args.append(','.join(self.__proxies))

        if 0 != len(self.__exclude_ports):
            args.append('--exclude-ports ' + ','.join([str(p) for p in self.__exclude_ports]))

        if 0 != len(self.__ports):
            args.append('-p' + ','.join([str(p) for p in self.__ports]))
        elif None != self.__top_ports:
            args.append('--top-ports')
            args.append(self.__top_ports)

        if None != self.__port_ratio:
            args.append('--port-ratio')
            args.append(self.__port_ratio)

        if None != self.__num_hosts:
            args.append('-iR')
            args.append(self.__num_hosts)

        if None != self.__data:
            args.append('--data')
            args.append(self.__data)

        if None != self.__data_string:
            args.append('--data-string')
            args.append(self.__data_string)

        if None != self.__data_length:
            args.append('--data-length')
            args.append(self.__data_length)

        if None != self.__ip_options:
            args.append('--ip-options')
            args.append(self.__ip_options)

        if None != self.__ttl:
            args.append('--ttl')
            args.append(self.__ttl)

        if None != self.__spoof_mac:
            args.append('--spoof-mac')
            args.append(self.__spoof_mac)

        if None != self.__version_intensity:
            args.append('--version-intensity')
            args.append(self.__version_intensity)

        if None != self.__os_scan_limit:
            args.append('--osscan-limit')
            args.append(self.__os_scan_limit)

        if None != self.__timing:
            args.append('-T')
            args.append(self.__timing)

        if None != self.__min_hostgroup:
            args.append('--min-hostgroup')
            args.append(self.__min_hostgroup)

        if None != self.__max_hostgroup:
            args.append('--max-hostgroup')
            args.append(self.__max_hostgroup)

        if None != self.__min_rate:
            args.append('--min-rate')
            args.append(self.__min_rate)

        if None != self.__max_rate:
            args.append('--max-rate')
            args.append(self.__max_rate)

        if None != self.__min_rtt_timeout:
            args.append('--min-rtt-timeout')
            args.append(self.__min_rtt_timeout)

        if None != self.__max_rtt_timeout:
            args.append('--max-rtt-timeout')
            args.append(self.__max_rtt_timeout)

        if None != self.__min_parallelism:
            args.append('--min-parallelism')
            args.append(self.__min_parallelism)

        if None != self.__max_parallelism:
            args.append('--max-parallelism')
            args.append(self.__max_parallelism)

        if None != self.__host_timeout:
            args.append('--host-timeout')
            args.append(self.__host_timeout)

        if None != self.__max_retries:
            args.append('--max-retries')
            args.append(self.__max_retries)

        if None != self.__scan_delay:
            args.append('--scan-delay')
            args.append(self.__scan_delay)

        if None != self.__mtu:
            args.append('--mtu')
            args.append(self.__mtu)

        if None != self.__spoof_ip:
            args.append('-S')
            args.append(self.__spoof_ip)

        if None != self.__interface:
            args.append('-e')
            args.append(self.__interface)

        if None != self.__source_port:
            args.append('--source-port')
            args.append(self.__source_port)

        if None != self.__datadir:
            args.append('--datadir')
            args.append(self.__datadir)

        if 0 != len(self.__decoys):
            args.append('-D')
            args.append(','.join(self.__decoys))

        if self.__version_light:
            args.append('--version-light')

        if self.__version_all:
            args.append('--version-all')

        if self.__script_trace:
            args.append('--script-trace')

        if self.__os_detection:
            args.append('-O')

        if self.__os_guess:
            args.append('--osscan-guess')

        if self.__ipv6_scan:
            args.append('-6')

        if self.__misc_a:
            args.append('-A')

        if self.__version_trace:
            args.append('--version-trace')

        if self.__bad_sum:
            args.append('--badsum')

        if self.__privileged:
            args.append('--privileged')

        if self.__send_eth:
            args.append('--send-eth')

        if self.__send_ip:
            args.append('--send-ip')

        if self.__pn:
            args.append('-Pn')

        if self.__unprivileged:
            args.append('--unprivileged')

        if self.__system_dns:
            args.append('--system-dns')

        if self.__default_script:
            args.append('-sC')

        if self.__fast_mode:
            args.append('-F')

        if self.__scan_consecutively:
            args.append('-r')

        if self.__traceroute:
            args.append('--traceroute')

        if self.__service_discovery:
            args.append('-sV')

        if self.__always_dns_resolution:
            args.append('-R')
        elif self.__never_dns_resolution:
            args.append('-n')

        if 0 == len(self.__hosts):
            raise LogicException('Can\'t scan a target without set one.')

        args += self.__hosts

        return [str(a) for a in args]

    def add_args(self, argpaser=None):

        if None == argpaser:
            argpaser = argparse.ArgumentParser(description='Nmap scan with python')

        self.__argpaser = argpaser

        argpaser.add_argument('-H', '--host', dest='hosts', action='append', default=self.__hosts, required=True,
                              help='Hostnames, IP addresses, networks, etc to scan')

        self.__add_list_arg(argpaser, '--exclude', 'Hostnames, IP addresses, networks, etc not to scan',
                            self.__exclude_hosts)
        self.__add_list_arg(argpaser, '--dns-servers', 'Specify custom DNS servers', self.__dns_servers)
        self.__add_list_arg(argpaser, '-p', 'Only scan specified ports', self.__ports)
        self.__add_list_arg(argpaser, '--exclude-ports', 'Exclude the specified ports from scanning',
                            self.__exclude_ports)
        self.__add_list_arg(argpaser, '--script',
                            'Is a comma separated list of directories, script-files or script-categories',
                            self.__scripts)
        self.__add_list_arg(argpaser, '--script-args', 'Provide arguments to scripts. Format: <n1=v1,[n2=v2,...]>',
                            self.__script_args)
        self.__add_list_arg(argpaser, '-D', 'Cloak a scan with decoys', self.__decoys)
        self.__add_list_arg(argpaser, '--proxies', 'Relay connections through HTTP/SOCKS4 proxies', self.__proxies)

        self.__add_int_arg(argpaser, '-iR', 'Number of hosts, choose random targets', self.__num_hosts)
        self.__add_int_arg(argpaser, '--top-ports', 'Scan <number> most common ports', self.__top_ports)
        self.__add_int_arg(argpaser, '--port-ratio', 'Scan ports more common than <ratio>', self.__port_ratio)
        self.__add_int_arg(argpaser, '--version-intensity', 'Set from 0 (light) to 9 (try all probes)',
                           self.__version_intensity)
        self.__add_int_arg(argpaser, '--osscan-limit', 'Limit OS detection to promising targets', self.__os_scan_limit)
        self.__add_int_arg(argpaser, '-T', 'Set timing template (higher is faster)', self.__timing)
        self.__add_int_arg(argpaser, '--min-hostgroup', 'Minimum Parallel host scan group sizes', self.__min_hostgroup)
        self.__add_int_arg(argpaser, '--max-hostgroup', 'Maximum Parallel host scan group sizes', self.__max_hostgroup)
        self.__add_int_arg(argpaser, '--min-rate', 'Send packets no slower than <number> per second', self.__min_rate)
        self.__add_int_arg(argpaser, '--max-rate', 'Send packets no faster than <number> per second',
                           self.__max_rate)
        self.__add_int_arg(argpaser, '--min-parallelism', 'Minimum Probe parallelization', self.__min_parallelism)
        self.__add_int_arg(argpaser, '--max-parallelism', 'Maximum Probe parallelization', self.__max_parallelism)
        self.__add_int_arg(argpaser, '-g', 'Use given port number', self.__source_port)
        self.__add_int_arg(argpaser, '--data-length', 'Append random data to sent packets', self.__data_length)
        self.__add_int_arg(argpaser, '--ttl', 'Set IP time-to-live field', self.__ttl)

        self.__add_str_arg(argpaser, '--min-rtt-timeout', 'Minimum Specifies probe round trip time.',
                           self.__min_rtt_timeout)
        self.__add_str_arg(argpaser, '--max-rtt-timeout', 'Maximum Specifies probe round trip time.',
                           self.__max_rtt_timeout)
        self.__add_str_arg(argpaser, '--initial-rtt-timeout', 'Initial Specifies probe round trip time.',
                           self.__initial_rtt_timeout)
        self.__add_str_arg(argpaser, '--max-retries', 'Maximum Caps number of port scan probe retransmissions',
                           self.__max_retries)
        self.__add_str_arg(argpaser, '--host-timeout', 'Give up on target after this long', self.__max_parallelism)
        self.__add_str_arg(argpaser, '--scan-delay', 'Adjust delay between probes', self.__scan_delay)
        self.__add_str_arg(argpaser, '--max-scan-delay', 'Adjust maximum delay between probes', self.__max_scan_delay)
        self.__add_str_arg(argpaser, '--mtu', 'Fragment packets (optionally w/given MTU)', self.__mtu)
        self.__add_str_arg(argpaser, '-S', 'Spoof source address', self.__spoof_ip)
        self.__add_str_arg(argpaser, '-e', 'Use specified interface', self.__interface)
        self.__add_str_arg(argpaser, '--data', 'Append a custom payload to sent packets', self.__data)
        self.__add_str_arg(argpaser, '--data-string', 'Append a custom ASCII string to sent packets',
                           self.__data_string)
        self.__add_str_arg(argpaser, '--ip-options', 'Send packets with specified ip options', self.__ip_options)
        self.__add_str_arg(argpaser, '--spoof-mac', 'Spoof your MAC address', self.__spoof_mac)
        self.__add_str_arg(argpaser, '--datadir', 'Specify custom Nmap data file location', self.__datadir)

        self.__add_boolean_arg(argpaser, '-n', 'Never do DNS resolution', self.__never_dns_resolution)
        self.__add_boolean_arg(argpaser, '-R', 'Always resolve DNS', self.__always_dns_resolution)
        self.__add_boolean_arg(argpaser, '--system-dns', 'Use OS\'s DNS resolver', self.__system_dns)
        self.__add_boolean_arg(argpaser, '--traceroute', 'Trace hop path to each host', self.__traceroute)
        self.__add_boolean_arg(argpaser, '-F', 'Fast mode - Scan fewer ports than the default scan', self.__fast_mode)
        self.__add_boolean_arg(argpaser, '-r', 'Scan ports consecutively - don\'t randomize', self.__scan_consecutively)
        self.__add_boolean_arg(argpaser, '-sV', 'Probe open ports to determine service/version info',
                               self.__service_discovery)
        self.__add_boolean_arg(argpaser, '--version-light', 'Limit to most likely probes (intensity 2)',
                               self.__version_light)
        self.__add_boolean_arg(argpaser, '--version-all', 'Try every single probe (intensity 9)', self.__version_all)
        self.__add_boolean_arg(argpaser, '--version-trace', 'Show detailed version scan activity (for debugging)',
                               self.__version_trace)
        self.__add_boolean_arg(argpaser, '-sC', 'Equivalent to --script=default', self.__default_script)
        self.__add_boolean_arg(argpaser, '--script-trace', 'Show all data sent and received', self.__script_trace)
        self.__add_boolean_arg(argpaser, '-O', 'Enable OS detection', self.__os_detection)
        self.__add_boolean_arg(argpaser, '--osscan-guess', 'Guess OS more aggressively', self.__os_guess)
        self.__add_boolean_arg(argpaser, '--badsum', 'Send packets with a bogus TCP/UDP/SCTP checksum', self.__bad_sum)
        self.__add_boolean_arg(argpaser, '-6', 'Enable IPv6 scanning', self.__ipv6_scan)
        self.__add_boolean_arg(argpaser, '-A',
                               'Enable OS detection, version detection, script scanning, and traceroute', self.__misc_a)
        self.__add_boolean_arg(argpaser, '--send-eth', 'Send using raw ethernet frames', self.__send_eth)
        self.__add_boolean_arg(argpaser, '--send-ip', 'Send using ip frames', self.__send_ip)
        self.__add_boolean_arg(argpaser, '--privileged', 'Assume that the user is fully privileged', self.__privileged)
        self.__add_boolean_arg(argpaser, '-Pn', 'Treat all hosts as online', self.__pn)
        self.__add_boolean_arg(argpaser, '--unprivileged', 'Assume the user lacks raw socket unprivileged',
                               self.__unprivileged)

    def configure(self, args=None):
        if None == args:
            if None == self.__argpaser:
                raise LogicException('You must call NmapArgs.add_cli_args() first')
            args = self.__argpaser.parse_args()

        self.__hosts = self.__get_arg(args, '--hosts')
        self.__exclude_hosts = self.__get_arg(args, '--exclude')
        self.__dns_servers = self.__get_arg(args, '--dns-servers')
        self.__ports = self.__get_arg(args, '-p')
        self.__exclude_ports = self.__get_arg(args, '--exclude-ports')
        self.__scripts = self.__get_arg(args, '--script')
        self.__script_args = self.__get_arg(args, '--script-args')
        self.__decoys = self.__get_arg(args, '-D')
        self.__proxies = self.__get_arg(args, '--proxies')
        self.__num_hosts = self.__get_arg(args, '-iR')
        self.__top_ports = self.__get_arg(args, '--top-ports')
        self.__port_ratio = self.__get_arg(args, '--port-ratio')
        self.__version_intensity = self.__get_arg(args, '--version-intensity')
        self.__os_scan_limit = self.__get_arg(args, '--osscan-limit')
        self.__timing = self.__get_arg(args, '-T')
        self.__min_hostgroup = self.__get_arg(args, '--min-hostgroup')
        self.__max_hostgroup = self.__get_arg(args, '--max-hostgroup')
        self.__min_rate = self.__get_arg(args, '--min-rate')
        self.__max_rate = self.__get_arg(args, '--max-rate')
        self.__min_parallelism = self.__get_arg(args, '--min-parallelism')
        self.__max_parallelism = self.__get_arg(args, '--max-parallelism')
        self.__source_port = self.__get_arg(args, '-g')
        self.__data_length = self.__get_arg(args, '--data-length', )
        self.__ttl = self.__get_arg(args, '--ttl')
        self.__min_rtt_timeout = self.__get_arg(args, '--min-rtt-timeout')
        self.__max_rtt_timeout = self.__get_arg(args, '--max-rtt-timeout')
        self.__initial_rtt_timeout = self.__get_arg(args, '--initial-rtt-timeout', )
        self.__max_retries = self.__get_arg(args, '--max-retries')
        self.__max_parallelism = self.__get_arg(args, '--host-timeout')
        self.__scan_delay = self.__get_arg(args, '--scan-delay')
        self.__max_scan_delay = self.__get_arg(args, '--max-scan-delay')
        self.__mtu = self.__get_arg(args, '--mtu')
        self.__spoof_ip = self.__get_arg(args, '-S')
        self.__interface = self.__get_arg(args, '-e')
        self.__data = self.__get_arg(args, '--data')
        self.__data_string = self.__get_arg(args, '--data-string')
        self.__ip_options = self.__get_arg(args, '--ip-options')
        self.__spoof_mac = self.__get_arg(args, '--spoof-mac')
        self.__datadir = self.__get_arg(args, '--datadir')
        self.__never_dns_resolution = self.__get_bool_arg(args, '-n', self.__never_dns_resolution)
        self.__always_dns_resolution = self.__get_bool_arg(args, '-R', self.__always_dns_resolution)
        self.__system_dns = self.__get_bool_arg(args, '--system-dns', self.__system_dns)
        self.__traceroute = self.__get_bool_arg(args, '--traceroute', self.__traceroute)
        self.__fast_mode = self.__get_bool_arg(args, '-F', self.__fast_mode)
        self.__scan_consecutively = self.__get_bool_arg(args, '-r', self.__scan_consecutively)
        self.__service_discovery = self.__get_bool_arg(args, '-sV', self.__service_discovery)
        self.__version_light = self.__get_bool_arg(args, '--version-light', self.__version_light)
        self.__version_all = self.__get_bool_arg(args, '--version-all', self.__version_all)
        self.__version_trace = self.__get_bool_arg(args, '--version-trace', self.__version_trace)
        self.__default_script = self.__get_bool_arg(args, '-sC', self.__default_script)
        self.__script_trace = self.__get_bool_arg(args, '--script-trace', self.__script_trace)
        self.__os_detection = self.__get_bool_arg(args, '-O', self.__os_detection)
        self.__os_guess = self.__get_bool_arg(args, '--osscan-guess', self.__os_guess)
        self.__bad_sum = self.__get_bool_arg(args, '--badsum', self.__bad_sum)
        self.__ipv6_scan = self.__get_bool_arg(args, '-6', self.__ipv6_scan)
        self.__misc_a = self.__get_bool_arg(args, '-A', self.__misc_a)
        self.__send_eth = self.__get_bool_arg(args, '--send-eth', self.__send_eth)
        self.__send_ip = self.__get_bool_arg(args, '--send-ip', self.__send_ip)
        self.__privileged = self.__get_bool_arg(args, '--privileged', self.__privileged)
        self.__unprivileged = self.__get_bool_arg(args, '--unprivileged', self.__unprivileged)
        self.__pn = self.__get_bool_arg(args, '-Pn', self.__pn)

    def __get_bool_arg(self, args, param, enabled):
        storeparam = param.replace('-', '')
        if enabled:
            return not getattr(args, 'not{param}'.format(param=storeparam))
        return getattr(args, '{param}'.format(param=storeparam))

    def __get_arg(self, args, param):
        storeparam = param.replace('-', '')

        return getattr(args, '{param}'.format(param=storeparam))

    def __add_boolean_arg(self, argpaser, param, description, enabled):

        storeparam = param.replace('-', '')
        if enabled:
            argpaser.add_argument('--not{param}'.format(param=param), dest='not{param}'.format(param=storeparam),
                                  required=False, action='store_true', help='Disable {desc}'.format(desc=description))
        else:
            argpaser.add_argument('{param}'.format(param=param), dest='{param}'.format(param=storeparam),
                                  required=False, action='store_true', help='{desc}'.format(desc=description))

    def __add_list_arg(self, argpaser, param, description, default):

        storeparam = param.replace('-', '')
        argpaser.add_argument('{param}'.format(param=param), dest='{param}'.format(param=storeparam),
                              action='append', default=default, required=False, help='{desc}'.format(desc=description))

    def __add_int_arg(self, argpaser, param, description, default):

        storeparam = param.replace('-', '')
        argpaser.add_argument('{param}'.format(param=param), dest='{param}'.format(param=storeparam),
                              type=int, default=default, required=False, help='{desc}'.format(desc=description))

    def __add_str_arg(self, argpaser, param, description, default):

        storeparam = param.replace('-', '')
        argpaser.add_argument('{param}'.format(param=param), dest='{param}'.format(param=storeparam),
                              type=str, default=default, required=False, help='{desc}'.format(desc=description))

    def require_root(self):
        return self.__os_detection \
               or self.__traceroute
