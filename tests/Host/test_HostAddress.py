import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Host.HostAddress import HostAddress
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestHostAddress(BaseXMLTest):

    def create_instance(self, xml):
        return HostAddress(xml)

    def get_all_files(self):
        return ['testdata/Host/HostAddress-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Host/HostAddress-5.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', 'address'),
        ('testdata/Host/HostAddress-2.xml', 'address'),
        ('testdata/Host/HostAddress-3.xml', 'address'),
    ])
    def test_address(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_addr()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', 'ipv4'),
        ('testdata/Host/HostAddress-2.xml', 'ipv6'),
        ('testdata/Host/HostAddress-3.xml', 'mac'),
    ])
    def test_addrtype(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', 'vendor'),
        ('testdata/Host/HostAddress-2.xml', 'vendor'),
        ('testdata/Host/HostAddress-3.xml', 'vendor'),
    ])
    def test_vendor(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_vendor()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', True),
        ('testdata/Host/HostAddress-2.xml', False),
        ('testdata/Host/HostAddress-3.xml', False),
    ])
    def test_is_ipv4(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_ipv4()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', False),
        ('testdata/Host/HostAddress-2.xml', True),
        ('testdata/Host/HostAddress-3.xml', False),
    ])
    def test_is_ipv6(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_ipv6()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', True),
        ('testdata/Host/HostAddress-2.xml', True),
        ('testdata/Host/HostAddress-3.xml', False),
    ])
    def test_is_ip(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_ip()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostAddress-1.xml', False),
        ('testdata/Host/HostAddress-2.xml', False),
        ('testdata/Host/HostAddress-3.xml', True),
    ])
    def test_is_mac(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_mac()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize(("filepath", "expected_error"), [
        ('testdata/Host/HostAddress-5.xml', 'addr'),
    ])
    def test_error_on_missing_required_param(self, filepath, expected_error):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/HostAddress-1.xml', 'testdata/Host/HostAddress-1.xml', True),
        ('testdata/Host/HostAddress-1.xml', 'testdata/Host/HostAddress-2.xml', False),
        ('testdata/Host/HostAddress-1.xml', 'testdata/Host/HostAddress-3.xml', False),
        ('testdata/Host/HostAddress-2.xml', 'testdata/Host/HostAddress-1.xml', False),
        ('testdata/Host/HostAddress-2.xml', 'testdata/Host/HostAddress-2.xml', True),
        ('testdata/Host/HostAddress-2.xml', 'testdata/Host/HostAddress-3.xml', False),
        ('testdata/Host/HostAddress-3.xml', 'testdata/Host/HostAddress-1.xml', False),
        ('testdata/Host/HostAddress-3.xml', 'testdata/Host/HostAddress-2.xml', False),
        ('testdata/Host/HostAddress-3.xml', 'testdata/Host/HostAddress-3.xml', True),
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
