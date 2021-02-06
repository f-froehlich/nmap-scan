import pytest

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestReverseIndex(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/ReverseIndex-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Scripts/InvalidScript-1.xml']

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/ReverseIndex-' + str(i) + '.xml' for i in range(1, 3)])
    def test_id(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'reverse-index' == e.get_id()

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/ReverseIndex-' + str(i) + '.xml' for i in range(1, 3)])
    def test_output(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'scriptOutput' == e.get_output()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/ReverseIndex-1.xml', {'port1/proto': ['ip1', 'ip2'], 'port2/proto': ['ip1', 'ip3']}),
        ('testdata/Scripts/ReverseIndex-2.xml', {'port1/proto': ['ip1', 'ip2'], 'port2/proto': ['ip1', 'ip2']}),
    ])
    def test_ips(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert len(expected) == len(e.get_port_ip_map())
        for key in expected:
            assert compare_lists(expected[key], e.get_port_ip_map().get(key, []))
            assert compare_lists(expected[key], e.get_ips_for_port(key.split('/')[0], key.split('/')[1]))

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/ReverseIndex-1.xml', 'testdata/Scripts/ReverseIndex-1.xml', True),
        ('testdata/Scripts/ReverseIndex-1.xml', 'testdata/Scripts/ReverseIndex-2.xml', False),
        ('testdata/Scripts/ReverseIndex-2.xml', 'testdata/Scripts/ReverseIndex-1.xml', False),
        ('testdata/Scripts/ReverseIndex-2.xml', 'testdata/Scripts/ReverseIndex-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
