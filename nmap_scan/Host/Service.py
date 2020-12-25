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

from nmap_scan.CompareHelper import compare_lists


class Service:

    def __init__(self, xml):
        self.__xml = xml
        self.__name = None
        self.__conf = None
        self.__method = None
        self.__version = None
        self.__product = None
        self.__extrainfo = None
        self.__tunnel = None
        self.__proto = None
        self.__rpcnum = None
        self.__lowver = None
        self.__highver = None
        self.__hostname = None
        self.__ostype = None
        self.__devicetype = None
        self.__servicefp = None
        self.__cpes = []
        self.__parse_xml()

    def equals(self, other):
        return isinstance(other, Service) \
               and self.__name == other.get_name() \
               and self.__conf == other.get_conf() \
               and self.__method == other.get_method() \
               and self.__version == other.get_version() \
               and self.__product == other.get_product() \
               and self.__extrainfo == other.get_extra_info() \
               and self.__tunnel == other.get_tunnel() \
               and self.__proto == other.get_proto() \
               and self.__rpcnum == other.get_rpc_num() \
               and self.__lowver == other.get_low_version() \
               and self.__highver == other.get_high_version() \
               and self.__hostname == other.get_hostname() \
               and self.__ostype == other.get_os_type() \
               and self.__devicetype == other.get_device_type() \
               and self.__servicefp == other.get_service_fp() \
               and compare_lists(self.__cpes, other.get_cpes())

    def get_xml(self):
        return self.__xml

    def get_cpes(self):
        return self.__cpes

    def get_product(self):
        return self.__product

    def get_conf(self):
        return self.__conf

    def get_method(self):
        return self.__method

    def get_version(self):
        return self.__version

    def get_extra_info(self):
        return self.__extrainfo

    def get_tunnel(self):
        return self.__tunnel

    def get_proto(self):
        return self.__proto

    def get_rpc_num(self):
        return self.__rpcnum

    def get_low_version(self):
        return self.__lowver

    def get_high_version(self):
        return self.__highver

    def get_hostname(self):
        return self.__hostname

    def get_os_type(self):
        return self.__ostype

    def get_device_type(self):
        return self.__devicetype

    def get_service_fp(self):
        return self.__servicefp

    def get_name(self):
        return self.__name

    def __parse_xml(self):
        logging.info('Parsing Service')
        attr = self.__xml.attrib
        self.__name = attr['name']
        self.__conf = attr['conf']
        self.__method = attr['method']
        self.__version = attr.get('version', None)
        self.__product = attr.get('product', None)
        self.__extrainfo = attr.get('extrainfo', None)
        self.__hostname = attr.get('hostname', None)
        self.__ostype = attr.get('ostype', None)
        self.__devicetype = attr.get('devicetype', None)
        self.__servicefp = attr.get('servicefp', None)
        self.__tunnel = attr.get('tunnel', None)
        self.__proto = attr.get('proto', None)
        self.__rpcnum = int(attr['rpcnum']) if None != attr.get('rpcnum', None) else None
        self.__lowver = int(attr['lowver']) if None != attr.get('lowver', None) else None
        self.__highver = int(attr['highver']) if None != attr.get('highver', None) else None

        logging.debug('Name: "{name}"'.format(name=self.__name))
        logging.debug('Conf: "{conf}"'.format(conf=self.__conf))
        logging.debug('Method: "{method}"'.format(method=self.__method))
        logging.debug('Version: "{version}"'.format(version=self.__version))
        logging.debug('Product: "{product}"'.format(product=self.__product))
        logging.debug('Extra info: "{info}"'.format(info=self.__extrainfo))
        logging.debug('Hostname: "{name}"'.format(name=self.__hostname))
        logging.debug('OS type: "{ostype}"'.format(ostype=self.__ostype))
        logging.debug('Device type: "{devcetype}"'.format(devcetype=self.__devicetype))
        logging.debug('Service FP: "{servicefp}"'.format(servicefp=self.__servicefp))
        logging.debug('RPC num: "{rpcnum}"'.format(rpcnum=self.__rpcnum))
        logging.debug('Low version: "{version}"'.format(version=self.__lowver))
        logging.debug('High version: "{version}"'.format(version=self.__highver))
        logging.debug('Tunnel: "{tunnel}"'.format(tunnel=self.__tunnel))
        logging.debug('Proto: "{proto}"'.format(proto=self.__proto))

        for cpe in self.__xml.findall('cpe'):
            logging.debug('CPE: "{cpe}"'.format(cpe=cpe.text))
            self.__cpes.append(cpe.text)
