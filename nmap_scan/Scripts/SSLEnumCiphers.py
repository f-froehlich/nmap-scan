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
from nmap_scan.Scripts.Script import Script


class SSLEnumCiphers(Script):

    def __init__(self, xml):
        Script.__init__(self, xml)
        self.__xml = xml
        self.__protocols = {}
        self.__least_strength = None
        self.__parse_xml()

    def equals(self, other):
        status = isinstance(other, SSLEnumCiphers) \
                 and Script.equals(self, other) \
                 and self.__least_strength == other.get_least_strength() \
                 and len(self.__protocols) == len(other.get_protocols())

        if status:
            for own_protocol in self.__protocols:
                other_protocol = other.get_protocol(own_protocol)
                if None == other_protocol or not other_protocol.equals(self.__protocols[own_protocol]):
                    return False
            for other_protocol in other.get_protocols():
                own_protocol = self.get_protocol(other_protocol)
                if None == own_protocol or not own_protocol.equals(other.get_protocol(other_protocol)):
                    # I think this could never happen because we can't add the same protocol more than once
                    # and it also will never returned from the script so it is already compared with the
                    # privies loop
                    return False

        return status

    def get_xml(self):
        return self.__xml

    def get_protocols(self):
        return self.__protocols

    def get_protocol(self, version):
        return self.__protocols.get(version, None)

    def get_least_strength(self):
        return self.__least_strength

    def __parse_xml(self):

        logging.info('Parsing SSLEnumCiphers')

        xml_tables = self.__xml.findall('table')
        for xml_table in xml_tables:
            self.__protocols[xml_table.attrib['key'].lower()] = SSLEnumCiphersProtocol(xml_table)

        for xml_elements in self.__xml.findall('elem'):
            if 'least strength' == xml_elements.attrib['key']:
                self.__least_strength = xml_elements.text
        logging.debug('Least strength: "{strength}"'.format(strength=self.__least_strength))


class SSLEnumCiphersProtocol:

    def __init__(self, xml):
        self.__xml = xml
        self.__ciphers = []
        self.__compressors = None
        self.__least_strength = None
        self.__cipher_preference = None
        self.__protocol_version = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_ciphers(self):
        return self.__ciphers

    def get_compressor(self):
        return self.__compressors

    def get_least_strength(self):
        return self.__least_strength

    def get_cipher_preference(self):
        return self.__cipher_preference

    def get_protocol_version(self):
        return self.__protocol_version

    def equals(self, other):
        status = isinstance(other, SSLEnumCiphersProtocol) \
                 and self.__protocol_version == other.get_protocol_version() \
                 and self.__compressors == other.get_compressor() \
                 and self.__cipher_preference == other.get_cipher_preference() \
                 and self.__least_strength == other.get_least_strength() \
                 and len(self.__ciphers) == len(other.get_ciphers())

        if status:
            for own_cipher in self.__ciphers:
                exist = False
                for other_cipher in other.get_ciphers():
                    if own_cipher.equals(other_cipher):
                        exist = True
                        break

                if not exist:
                    return False

            for other_cipher in other.get_ciphers():
                exist = False
                for own_cipher in self.__ciphers:
                    if own_cipher.equals(other_cipher):
                        exist = True
                        break

                if not exist:
                    return False

        return status

    def __parse_xml(self):

        logging.info('Parsing SSLEnumCiphersProtocol')
        self.__protocol_version = self.__xml.attrib['key'].lower()

        for xml_table in self.__xml.findall('table'):
            if 'ciphers' == xml_table.get('key', None):
                for cipher_table in xml_table.findall('table'):
                    self.__ciphers.append(SSLEnumCiphersCipher(cipher_table))

            elif 'compressors' == xml_table.get('key', None):
                for compressor_table in xml_table.findall('elem'):
                    self.__compressors = compressor_table.text

        for xml_elements in self.__xml.findall('elem'):
            if 'cipher preference' == xml_elements.get('key', None):
                self.__cipher_preference = xml_elements.text

        least_strength = 'A'
        for cipher in self.__ciphers:
            least_strength = cipher.get_strength() \
                if cipher.is_worse_than_strength(least_strength) else least_strength

        self.__least_strength = least_strength

        logging.debug('Protocol: "{protocol}"'.format(protocol=self.__protocol_version))
        logging.debug('Compressor: "{compressor}"'.format(compressor=self.__compressors))
        logging.debug('Cipher preference: "{cipher_preference}"'.format(cipher_preference=self.__cipher_preference))
        logging.debug('Least strength: "{strength}"'.format(strength=self.__least_strength))


class SSLEnumCiphersCipher:

    def __init__(self, xml):
        self.__xml = xml
        self.__strength = None
        self.__name = None
        self.__key_info = None
        self.__parse_xml()

    def get_xml(self):
        return self.__xml

    def get_strength(self):
        return self.__strength

    def get_name(self):
        return self.__name

    def get_key_info(self):
        return self.__key_info

    def is_worse_than(self, cipher):
        return self.is_worse_than_strength(cipher.get_strength())

    def is_worse_than_strength(self, strength):

        return CipherCompare.a_worse_b(self.__strength, strength)

    def is_worse_equals_than(self, cipher):
        return self.is_worse_equals_than_strength(cipher.get_strength())

    def is_worse_equals_than_strength(self, strength):

        return CipherCompare.a_worse_equals_b(self.__strength, strength)

    def is_better_than(self, cipher):
        return self.is_better_than_strength(cipher.get_strength())

    def is_better_than_strength(self, strength):

        return CipherCompare.a_better_b(self.__strength, strength)

    def is_better_equals_than(self, cipher):
        return self.is_better_equals_than_strength(cipher.get_strength())

    def is_better_equals_than_strength(self, strength):

        return CipherCompare.a_better_equals_b(self.__strength, strength)

    def equals(self, other):
        return isinstance(other, SSLEnumCiphersCipher) \
               and self.__name == other.get_name() \
               and self.__key_info == other.get_key_info() \
               and CipherCompare.a_equals_b(self.__strength, other.get_strength())

    def __parse_xml(self):

        logging.info('Parsing SSLEnumCiphersCiphers')

        for xml_element in self.__xml.findall('elem'):
            key = xml_element.attrib['key']
            if 'strength' == key:
                self.__strength = xml_element.text
            elif 'name' == key:
                self.__name = xml_element.text
            elif 'kex_info' == key:
                self.__key_info = xml_element.text

        logging.debug('Cipher: "{name}" ({key_info}) - "{strength}"'.format(name=self.__name, strength=self.__strength,
                                                                            key_info=self.__key_info))


class CipherCompare:

    @staticmethod
    def a_lower_b(a, b):
        return CipherCompare.map_strength(a) < CipherCompare.map_strength(b)

    @staticmethod
    def a_lower_equals_b(a, b):
        return CipherCompare.map_strength(a) <= CipherCompare.map_strength(b)

    @staticmethod
    def a_better_b(a, b):
        return CipherCompare.a_lower_b(a, b)

    @staticmethod
    def a_better_equals_b(a, b):
        return CipherCompare.a_lower_equals_b(a, b)

    @staticmethod
    def a_grater_b(a, b):
        return CipherCompare.map_strength(a) > CipherCompare.map_strength(b)

    @staticmethod
    def a_grater_equals_b(a, b):
        return CipherCompare.map_strength(a) >= CipherCompare.map_strength(b)

    @staticmethod
    def a_worse_b(a, b):
        return CipherCompare.a_grater_b(a, b)

    @staticmethod
    def a_worse_equals_b(a, b):
        return CipherCompare.a_grater_equals_b(a, b)

    @staticmethod
    def a_equals_b(a, b):
        return CipherCompare.map_strength(a) == CipherCompare.map_strength(b)

    @staticmethod
    def a_not_equals_b(a, b):
        return CipherCompare.map_strength(a) != CipherCompare.map_strength(b)

    @staticmethod
    def map_strength(strength):
        logging.debug('Map strength "{strength}"'.format(strength=strength))

        all_strength = {
            'A': 1,
            'B': 2,
            'C': 3,
            'D': 4,
            'E': 5,
            'F': 6,
        }

        mapped_strength = all_strength.get(strength.upper(), None)
        if None == mapped_strength:
            logging.info('Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength))
            raise LogicException('Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength))

        return mapped_strength

    @staticmethod
    def reverse_map_strength(strength):
        logging.debug('Reverse map strength "{strength}"'.format(strength=strength))
        all_strength = {
            1: 'A',
            2: 'B',
            3: 'C',
            4: 'D',
            5: 'E',
            6: 'F',
        }

        mapped_strength = all_strength.get(strength, None)
        if None == mapped_strength:
            logging.info('Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength))
            raise LogicException('Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength))

        return mapped_strength
