import pytest

from nmap_scan.CompareHelper import compare_lists
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestSSH2EnumAlgos(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSH/SSH2EnumAlgos-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/SSH/SSH2EnumAlgos-' + str(i) + '.xml' for i in range(1, 3)])
    def test_id(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'ssh2-enum-algos' == e.get_id()

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/SSH/SSH2EnumAlgos-' + str(i) + '.xml' for i in range(1, 3)])
    def test_output(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'scriptOutput' == e.get_output()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', ['kex_algorithms']),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', ['kex_algorithms']),
    ])
    def test_kex_algorithms(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert compare_lists(expected, e.get_kex_algorithms())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', {'other': ['other1']}),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', {'other': ['other1', 'other2']}),
    ])
    def test_other(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert len(expected) == len(e.get_other())
        for key in expected:
            assert compare_lists(expected[key], e.get_other().get(key, []))

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', ['compression_algorithms']),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', ['compression_algorithms']),
    ])
    def test_compression_algorithms(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert compare_lists(expected, e.get_compression_algorithms())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', ['mac_algorithms']),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', ['mac_algorithms']),
    ])
    def test_mac_algorithms(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert compare_lists(expected, e.get_mac_algorithms())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', ['encryption_algorithms']),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', ['encryption_algorithms']),
    ])
    def test_encryption_algorithms(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert compare_lists(expected, e.get_encryption_algorithms())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', ['server_host_key_algorithms']),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', ['server_host_key_algorithms']),
    ])
    def test_server_host_key_algorithms(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert compare_lists(expected, e.get_server_host_key_algorithms())

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', 'testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', True),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', 'testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', False),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', 'testdata/Scripts/SSH/SSH2EnumAlgos-1.xml', False),
        ('testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', 'testdata/Scripts/SSH/SSH2EnumAlgos-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
