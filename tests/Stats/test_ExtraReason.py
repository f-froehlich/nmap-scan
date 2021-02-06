import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.ExtraReason import ExtraReason
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.extraReason
class TestExtraReason(BaseXMLTest):

    def create_instance(self, xml):
        return ExtraReason(xml)

    def get_all_files(self):
        return ['testdata/Stats/ExtraReason-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/ExtraReason-' + str(i) + '.xml' for i in range(3, 5)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraReason-1.xml', 'reason'),
        ('testdata/Stats/ExtraReason-2.xml', 'reason2'),
    ])
    def test_reason(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraReason-1.xml', 'count'),
        ('testdata/Stats/ExtraReason-2.xml', 'count2'),
    ])
    def test_count(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_count()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraReason-6.xml', 'ip'),
    ])
    def test_proto(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_proto()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraReason-6.xml', 'ports'),
    ])
    def test_proto(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_ports()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ExtraReason-3.xml'])
    def test_error_on_missing_count(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ExtraReason-4.xml'])
    def test_error_on_missing_reason(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/ExtraReason-1.xml', 'testdata/Stats/ExtraReason-2.xml', False),
        ('testdata/Stats/ExtraReason-1.xml', 'testdata/Stats/ExtraReason-1.xml', True),
        ('testdata/Stats/ExtraReason-2.xml', 'testdata/Stats/ExtraReason-1.xml', False),
        ('testdata/Stats/ExtraReason-2.xml', 'testdata/Stats/ExtraReason-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
