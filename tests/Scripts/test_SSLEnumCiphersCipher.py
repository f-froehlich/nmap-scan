import pytest

from nmap_scan.Scripts.SSLEnumCiphers import SSLEnumCiphersCipher
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestSSLEnumCiphersCipher(BaseXMLTest):

    def create_instance(self, xml):
        return SSLEnumCiphersCipher(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml',
                'testdata/Scripts/SSLEnumCiphers/Cipher-3.xml']

    def get_all_invalid_files(self):
        return ['testdata/Scripts/InvalidScript-1.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'Name'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'Name2'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-3.xml', None)])
    def test_name(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_name()

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'keyInfo'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'keyInfo2'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-3.xml', None)])
    def test_key_info(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_key_info()

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'A'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'D'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Cipher-3.xml', None)])
    def test_strength(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_strength()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', False)])
    def test_is_worse_than(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        xml2 = self.create_xml(filepath2)
        e1 = self.create_instance(xml1)
        e2 = self.create_instance(xml2)

        assert expected == e1.is_worse_than(e2)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', True)])
    def test_is_worse_equals_than(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        xml2 = self.create_xml(filepath2)
        e1 = self.create_instance(xml1)
        e2 = self.create_instance(xml2)

        assert expected == e1.is_worse_equals_than(e2)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', False)])
    def test_is_better_than(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        xml2 = self.create_xml(filepath2)
        e1 = self.create_instance(xml1)
        e2 = self.create_instance(xml2)

        assert expected == e1.is_better_than(e2)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', True)])
    def test_is_better_equals_than(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        xml2 = self.create_xml(filepath2)
        e1 = self.create_instance(xml1)
        e2 = self.create_instance(xml2)

        assert expected == e1.is_better_equals_than(e2)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        xml2 = self.create_xml(filepath2)
        e1 = self.create_instance(xml1)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
