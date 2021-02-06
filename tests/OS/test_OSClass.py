import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.OS.OSClass import OSClass
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestOSClass(BaseXMLTest):

    def create_instance(self, xml):
        return OSClass(xml)

    def get_all_files(self):
        return ['testdata/OS/OSClass-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/OS/OSClass-3.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', 'vendor'),
        ('testdata/OS/OSClass-2.xml', 'vendor'),
    ])
    def test_vendor(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_vendor()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', 'type'),
        ('testdata/OS/OSClass-2.xml', 'type'),
    ])
    def test_type(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', 'osgen'),
        ('testdata/OS/OSClass-2.xml', 'osgen'),
    ])
    def test_osgen(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_generation()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', 33),
        ('testdata/OS/OSClass-2.xml', 33),
    ])
    def test_accuracy(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_accuracy()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', 'osfamily'),
        ('testdata/OS/OSClass-2.xml', 'osfamily'),
    ])
    def test_os_family(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_family()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSClass-1.xml', ['cpe1', 'cpe2']),
        ('testdata/OS/OSClass-2.xml', ['cpe1', 'cpe1']),
    ])
    def test_values(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert len(expected) == len(e.get_cpes())

        for c in e.get_cpes():
            assert c in expected
        for c in expected:
            assert c in e.get_cpes()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/OS/OSClass-3.xml'])
    def test_error_on_missing_osfamily(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/OS/OSClass-4.xml'])
    def test_error_on_missing_accuracy(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/OS/OSClass-5.xml'])
    def test_error_on_missing_vendor(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/OS/OSClass-1.xml', 'testdata/OS/OSClass-1.xml', True),
        ('testdata/OS/OSClass-1.xml', 'testdata/OS/OSClass-2.xml', False),
        ('testdata/OS/OSClass-2.xml', 'testdata/OS/OSClass-1.xml', False),
        ('testdata/OS/OSClass-2.xml', 'testdata/OS/OSClass-2.xml', True),
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
