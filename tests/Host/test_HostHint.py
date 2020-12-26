import pytest

from nmap_scan.CompareHelper import compare_lists_equal
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Host.HostHint import HostHint
from nmap_scan.Host.HostName import HostName
from nmap_scan.Stats.Status import Status
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestHostHint(BaseXMLTest):

    def create_instance(self, xml):
        return HostHint(xml)

    def get_all_files(self):
        return ['testdata/Host/HostHint-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostHint-1.xml', ['testdata/Host/HostAddress-1.xml']),
        ('testdata/Host/HostHint-2.xml', ['testdata/Host/HostAddress-1.xml']),
    ])
    def test_address(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        addr = []
        for a in expected:
            addr.append(HostAddress(self.create_xml(a)))

        assert compare_lists_equal(e.get_addresses(), addr)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostHint-1.xml', ['testdata/Host/HostName-1.xml']),
        ('testdata/Host/HostHint-2.xml', ['testdata/Host/HostName-3.xml']),
    ])
    def test_hostname(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        names = []
        for a in expected:
            names.append(HostName(self.create_xml(a)))

        assert compare_lists_equal(e.get_hostnames(), names)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostHint-1.xml', ['testdata/Stats/Status-1.xml']),
        ('testdata/Host/HostHint-2.xml', ['testdata/Stats/Status-1.xml']),
    ])
    def test_statuses(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        statuses = []
        for a in expected:
            statuses.append(Status(self.create_xml(a)))

        assert compare_lists_equal(e.get_statuses(), statuses)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/HostHint-1.xml', 'testdata/Host/HostHint-1.xml', True),
        ('testdata/Host/HostHint-1.xml', 'testdata/Host/HostHint-2.xml', False),
        ('testdata/Host/HostHint-2.xml', 'testdata/Host/HostHint-1.xml', False),
        ('testdata/Host/HostHint-2.xml', 'testdata/Host/HostHint-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
