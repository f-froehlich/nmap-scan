import pytest

from nmap_scan.Scripts.SSLEnumCiphers import SSLEnumCiphersProtocol
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestSSLEnumCiphers(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSLEnumCiphers/Script-1.xml']

    def get_all_invalid_files(self):
        return ['testdata/Scripts/InvalidScript-1.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Script-1.xml', 'D')])
    def test_get_least_strength(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_least_strength()

    @pytest.mark.parametrize(("filepath", "protocols"), [
        ('testdata/Scripts/SSLEnumCiphers/Script-1.xml', ['testdata/Scripts/SSLEnumCiphers/Protocol-1.xml'])
    ])
    def test_key_info(self, filepath, protocols):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        expected_protocols = []
        for p in protocols:
            xml = self.create_xml(p)
            expected_protocols.append(SSLEnumCiphersProtocol(xml))

        assert len(expected_protocols) == len(e.get_protocols())

        for expected in expected_protocols:
            exist = False
            protocols = e.get_protocols()
            for p in protocols:
                if expected.equals(protocols[p]):
                    assert not exist
                    exist = True

            assert exist

        for expected in expected_protocols:
            assert expected.equals(e.get_protocol(expected.get_protocol_version()))

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('Script-1.xml', 'Script-1.xml', True),
        ('Script-1.xml', 'Script-2.xml', False),
        ('Script-1.xml', 'Script-3.xml', False),
        ('Script-2.xml', 'Script-1.xml', False),
        ('Script-2.xml', 'Script-2.xml', True),
        ('Script-2.xml', 'Script-3.xml', False),
        ('Script-3.xml', 'Script-1.xml', False),
        ('Script-3.xml', 'Script-2.xml', False),
        ('Script-3.xml', 'Script-3.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        basepath = 'testdata/Scripts/SSLEnumCiphers/'
        xml1 = self.create_xml(basepath + filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(basepath + filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
