import pytest

from nmap_scan.Host.HostName import HostName
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestHostName(BaseXMLTest):

    def create_instance(self, xml):
        return HostName(xml)

    def get_all_files(self):
        return ['testdata/Host/HostName-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostName-1.xml', 'name'),
        ('testdata/Host/HostName-2.xml', None),
    ])
    def test_name(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_name()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/HostName-1.xml', 'type'),
        ('testdata/Host/HostName-2.xml', None),
    ])
    def test_type(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/HostName-1.xml', 'testdata/Host/HostName-1.xml', True),
        ('testdata/Host/HostName-1.xml', 'testdata/Host/HostName-2.xml', False),
        ('testdata/Host/HostName-2.xml', 'testdata/Host/HostName-1.xml', False),
        ('testdata/Host/HostName-2.xml', 'testdata/Host/HostName-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
