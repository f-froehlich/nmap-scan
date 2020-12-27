import pytest

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Scripts.SSH.SSHHostkey import Key
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestSSHHostkey(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSH/SSHHostkey-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/SSH/SSHHostkey-' + str(i) + '.xml' for i in range(1, 3)])
    def test_id(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'ssh-hostkey' == e.get_id()

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/SSH/SSHHostkey-' + str(i) + '.xml' for i in range(1, 3)])
    def test_output(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'scriptOutput' == e.get_output()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/SSHHostkey-1.xml', ['testdata/Scripts/SSH/Key-1.xml', 'testdata/Scripts/SSH/Key-2.xml']),
        ('testdata/Scripts/SSH/SSHHostkey-2.xml', ['testdata/Scripts/SSH/Key-1.xml']),
    ])
    def test_keys(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        keys = []
        for k in expected:
            keys.append(Key(self.create_xml(k)))
        assert compare_lists_equal(keys, e.get_keys())

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSH/SSHHostkey-1.xml', 'testdata/Scripts/SSH/SSHHostkey-1.xml', True),
        ('testdata/Scripts/SSH/SSHHostkey-1.xml', 'testdata/Scripts/SSH/SSHHostkey-2.xml', False),
        ('testdata/Scripts/SSH/SSHHostkey-2.xml', 'testdata/Scripts/SSH/SSHHostkey-1.xml', False),
        ('testdata/Scripts/SSH/SSHHostkey-2.xml', 'testdata/Scripts/SSH/SSHHostkey-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
