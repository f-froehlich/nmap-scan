import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.Uptime import Uptime
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.uptime
class TestUptime(BaseXMLTest):

    def create_instance(self, xml):
        return Uptime(xml)

    def get_all_files(self):
        return ['testdata/Stats/Uptime-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/Uptime-' + str(i) + '.xml' for i in range(3, 4)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Uptime-1.xml', 10),
        ('testdata/Stats/Uptime-2.xml', 10),
    ])
    def test_seconds(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_seconds()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Uptime-1.xml', 'boottime'),
        ('testdata/Stats/Uptime-2.xml', None),
    ])
    def test_boot(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_last_boot()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Uptime-3.xml'])
    def test_error_on_missing_seconds(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/Uptime-1.xml', 'testdata/Stats/Uptime-2.xml', False),
        ('testdata/Stats/Uptime-1.xml', 'testdata/Stats/Uptime-1.xml', True),
        ('testdata/Stats/Uptime-2.xml', 'testdata/Stats/Uptime-1.xml', False),
        ('testdata/Stats/Uptime-2.xml', 'testdata/Stats/Uptime-2.xml', True),
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
