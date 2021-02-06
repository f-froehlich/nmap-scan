import pytest

from nmap_scan.Scripts.SSH.SSHHostkey import Key
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestKey(BaseXMLTest):

    def create_instance(self, xml):
        return Key(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSH/Key-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Scripts/InvalidScript-1.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/Key-1.xml', 'key'),
        ('testdata/Scripts/SSH/Key-2.xml', 'key'),
    ])
    def test_key(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_key()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/Key-1.xml', 'fingerprint'),
        ('testdata/Scripts/SSH/Key-2.xml', 'fingerprint2'),
    ])
    def test_fingerprint(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_fingerprint()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/Key-1.xml', 'ssh-rsa'),
        ('testdata/Scripts/SSH/Key-2.xml', 'ssh-rsa'),
    ])
    def test_type(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSH/Key-1.xml', 3072),
        ('testdata/Scripts/SSH/Key-2.xml', 3072),
    ])
    def test_bits(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_bits()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSH/Key-1.xml', 'testdata/Scripts/SSH/Key-1.xml', True),
        ('testdata/Scripts/SSH/Key-1.xml', 'testdata/Scripts/SSH/Key-2.xml', False),
        ('testdata/Scripts/SSH/Key-2.xml', 'testdata/Scripts/SSH/Key-1.xml', False),
        ('testdata/Scripts/SSH/Key-2.xml', 'testdata/Scripts/SSH/Key-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)

        if expected:
            assert e1 == e2
            assert not e1 != e2
        else:
            assert not e1 == e2
            assert e1 != e2
