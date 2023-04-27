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

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Validator import validate
from xml.etree.ElementTree import Element as XMLElement
from typing import TypeVar, Dict, Union, List

T = TypeVar('T', bound='Service')


class Service:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__name: Union[str, None] = None
        self.__conf: Union[str, None] = None
        self.__method: Union[str, None] = None
        self.__version: Union[str, None] = None
        self.__product: Union[str, None] = None
        self.__extrainfo: Union[str, None] = None
        self.__tunnel: Union[str, None] = None
        self.__proto: Union[str, None] = None
        self.__rpcnum: Union[int, None] = None
        self.__lowver: Union[int, None] = None
        self.__highver: Union[int, None] = None
        self.__hostname: Union[str, None] = None
        self.__ostype: Union[str, None] = None
        self.__devicetype: Union[str, None] = None
        self.__servicefp: Union[str, None] = None
        self.__cpes: List[str] = []
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "name", self.__name
        yield "conf", self.__conf
        yield "method", self.__method
        if None is not self.__version:
            yield "version", self.__version
        if None is not self.__product:
            yield "product", self.__product
        if None is not self.__extrainfo:
            yield "extrainfo", self.__extrainfo
        if None is not self.__tunnel:
            yield "tunnel", self.__tunnel
        if None is not self.__proto:
            yield "proto", self.__proto
        if None is not self.__rpcnum:
            yield "rpcnum", self.__rpcnum
        if None is not self.__lowver:
            yield "lowver", self.__lowver
        if None is not self.__highver:
            yield "highver", self.__highver
        if None is not self.__hostname:
            yield "hostname", self.__hostname
        if None is not self.__ostype:
            yield "ostype", self.__ostype
        if None is not self.__devicetype:
            yield "devicetype", self.__devicetype
        if None is not self.__servicefp:
            yield "servicefp", self.__servicefp
        yield "cpes", self.__cpes

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('service')

        if None is not d.get('name', None):
            xml.attrib['name'] = d['name']
        if None is not d.get('conf', None):
            xml.attrib['conf'] = str(d['conf'])
        if None is not d.get('method', None):
            xml.attrib['method'] = d['method']
        if None is not d.get('version', None):
            xml.attrib['version'] = str(d['version'])
        if None is not d.get('product', None):
            xml.attrib['product'] = d['product']
        if None is not d.get('extrainfo', None):
            xml.attrib['extrainfo'] = d['extrainfo']
        if None is not d.get('tunnel', None):
            xml.attrib['tunnel'] = d['tunnel']
        if None is not d.get('proto', None):
            xml.attrib['proto'] = d['proto']
        if None is not d.get('rpcnum', None):
            xml.attrib['rpcnum'] = str(d['rpcnum'])
        if None is not d.get('lowver', None):
            xml.attrib['lowver'] = str(d['lowver'])
        if None is not d.get('highver', None):
            xml.attrib['highver'] = str(d['highver'])
        if None is not d.get('hostname', None):
            xml.attrib['hostname'] = d['hostname']
        if None is not d.get('ostype', None):
            xml.attrib['ostype'] = d['ostype']
        if None is not d.get('devicetype', None):
            xml.attrib['devicetype'] = d['devicetype']
        if None is not d.get('servicefp', None):
            xml.attrib['servicefp'] = d['servicefp']

        if None is not d.get('cpes', None):
            if None is not d.get('cpes', None):
                for cpe in d['cpes']:
                    cpe_xml = etree.Element('cpe')
                    cpe_xml.text = cpe
                    xml.append(cpe_xml)

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Service(Service.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
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

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_cpes(self) -> List[str]:
        return self.__cpes

    def get_product(self) -> Union[str, None]:
        return self.__product

    def get_conf(self) -> str:
        return self.__conf

    def get_method(self) -> str:
        return self.__method

    def get_version(self) -> Union[str, None]:
        return self.__version

    def get_extra_info(self) -> Union[str, None]:
        return self.__extrainfo

    def get_tunnel(self) -> Union[str, None]:
        return self.__tunnel

    def get_proto(self) -> Union[str, None]:
        return self.__proto

    def get_rpc_num(self) -> Union[int, None]:
        return self.__rpcnum

    def get_low_version(self) -> Union[int, None]:
        return self.__lowver

    def get_high_version(self) -> Union[int, None]:
        return self.__highver

    def get_hostname(self) -> Union[str, None]:
        return self.__hostname

    def get_os_type(self) -> Union[str, None]:
        return self.__ostype

    def get_device_type(self) -> Union[str, None]:
        return self.__devicetype

    def get_service_fp(self) -> Union[str, None]:
        return self.__servicefp

    def get_name(self) -> str:
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
        self.__rpcnum = int(attr['rpcnum']) if None is not attr.get('rpcnum', None) else None
        self.__lowver = int(attr['lowver']) if None is not attr.get('lowver', None) else None
        self.__highver = int(attr['highver']) if None is not attr.get('highver', None) else None

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
