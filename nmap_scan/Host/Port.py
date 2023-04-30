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
from typing import TypeVar, Dict, Union, List
from xml.etree.ElementTree import Element as XMLElement

from lxml import etree

from nmap_scan.CompareHelper import compare_script_maps
from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Host.Service import Service
from nmap_scan.Scripts.Script import Script
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Stats.State import State
from nmap_scan.Validator import validate

T = TypeVar('T', bound='Port')


class Port:

    def __init__(self, xml: XMLElement, validate_xml: bool = True):
        if validate_xml:
            validate(xml)
        self.__xml: XMLElement = xml
        self.__protocol: Union[str, None] = None
        self.__port: Union[int, None] = None
        self.__state: Union[State, None] = None
        self.__owner: Union[str, None] = None
        self.__service: Union[Service, None] = None
        self.__scripts: Dict[str, Union[List[Script], Script]] = {}
        self.__parse_xml()

    def __eq__(self, other: T) -> bool:
        return self.equals(other)

    def __ne__(self, other: T) -> bool:
        return not self.__eq__(other)

    def __iter__(self):
        yield "protocol", self.__protocol
        yield "port", self.__port
        if None is not self.__state:
            yield "state", dict(self.__state)
        if None is not self.__owner:
            yield "owner", self.__owner
        if None is not self.__service:
            yield "service", dict(self.__service)

        scripts = []
        for id in self.__scripts:
            script = self.__scripts[id]
            if isinstance(script, Script):
                scripts.append(dict(script))
            elif isinstance(script, list):
                for s in script:
                    scripts.append(dict(s))

        yield "scripts", scripts

    @staticmethod
    def dict_to_xml(d: Dict[str, any], validate_xml: bool = True) -> T:
        xml = etree.Element('port')
        if None is not d.get('protocol', None):
            xml.attrib['protocol'] = d.get('protocol', None)
        if None is not d.get('port', None):
            xml.attrib['portid'] = str(d.get('port', None))

        if None is not d.get('state', None):
            xml.append(State.dict_to_xml(d['state'], validate_xml))

        if None is not d.get('owner', None):
            owner_xml = etree.Element('owner')
            owner_xml.attrib['name'] = d.get('owner', None)
            xml.append(owner_xml)

        if None is not d.get('service', None):
            xml.append(Service.dict_to_xml(d['service'], validate_xml))

        if None is not d.get('scripts', None):
            for script_dict in d['scripts']:
                xml.append(Script.dict_to_xml(script_dict, validate_xml))

        if validate_xml:
            try:
                validate(xml)
            except NmapXMLParserException:
                raise NmapDictParserException()

        return xml

    @staticmethod
    def from_dict(d: Dict[str, any]) -> T:
        try:
            return Port(Port.dict_to_xml(d, False))
        except NmapXMLParserException:
            raise NmapDictParserException()

    def equals(self, other: T) -> bool:
        return isinstance(other, Port) \
            and self.__protocol == other.get_protocol() \
            and self.__port == other.get_port() \
            and self.__owner == other.get_owner() \
            and self.__state.equals(other.get_state()) \
            and self.__service.equals(other.get_service()) \
            and compare_script_maps(self.__scripts, other.get_scripts())

    def get_xml(self) -> XMLElement:
        return self.__xml

    def get_protocol(self) -> str:
        return self.__protocol

    def get_port(self) -> int:
        return self.__port

    def get_state(self) -> State:
        return self.__state

    def get_service(self) -> Union[Service, None]:
        return self.__service

    def get_scripts(self) -> Dict[str, Union[List[Script], Script]]:
        return self.__scripts

    def get_owner(self) -> Union[str, None]:
        return self.__owner

    def is_open(self) -> bool:
        return 'open' in self.__state.get_state()

    def is_filtered(self) -> bool:
        return 'filtered' in self.__state.get_state() and not self.is_unfiltered()

    def is_open_filtered(self) -> bool:
        return self.is_open() and self.is_filtered()

    def is_unfiltered(self) -> bool:
        return 'unfiltered' in self.__state.get_state()

    def is_closed(self) -> bool:
        return 'closed' in self.__state.get_state()

    def is_closed_filtered(self) -> bool:
        return self.is_closed() and self.is_filtered()

    def has_script(self, script_id: str) -> bool:
        return None is not self.__scripts.get(script_id, None)

    def get_script(self, script_id: str) -> Union[Script, None]:
        return self.__scripts.get(script_id, None)

    def is_ip_protocol(self) -> bool:
        return 'ip' == self.__protocol

    def is_sctp_protocol(self) -> bool:
        return 'sctp' == self.__protocol

    def is_tcp_protocol(self) -> bool:
        return 'tcp' == self.__protocol

    def is_udp_protocol(self) -> bool:
        return 'udp' == self.__protocol

    def __parse_xml(self):

        logging.info('Parsing Port')
        attr = self.__xml.attrib
        self.__protocol = attr['protocol']
        self.__port = int(attr['portid'])
        logging.debug('Port: "{port}"'.format(port=self.__port))
        logging.debug('Protocol: "{protocol}"'.format(protocol=self.__protocol))
        self.__state = State(self.__xml.find('state'), False)

        service = self.__xml.find('service')
        if None is not service:
            self.__service = Service(service, False)

        owner = self.__xml.find('owner')
        if None is not owner:
            self.__owner = owner.attrib['name']

        for script_xml in self.__xml.findall('script'):
            script = parse(script_xml, False)
            existing_script = self.__scripts.get(script.get_id(), None)
            if None is existing_script:
                self.__scripts[script.get_id()] = script
            elif isinstance(existing_script, list):
                self.__scripts[script.get_id()].append(script)
            else:
                self.__scripts[script.get_id()] = [existing_script, script]
