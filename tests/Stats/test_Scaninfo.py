import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.ScanInfo import ScanInfo
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.scaninfo
class TestScanInfo(BaseXMLTest):

    def create_instance(self, xml):
        return ScanInfo(xml)

    def get_all_files(self):
        return ['testdata/Stats/ScanInfo-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/ScanInfo-' + str(i) + '.xml' for i in range(6, 7)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 'syn'),
        ('testdata/Stats/ScanInfo-2.xml', 'bounce'),
    ])
    def test_type(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 'scanflags'),
        ('testdata/Stats/ScanInfo-2.xml', None),
    ])
    def test_scanflags(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_scan_flags()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 'tcp'),
        ('testdata/Stats/ScanInfo-2.xml', 'tcp'),
    ])
    def test_reason_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_protocol()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 10),
        ('testdata/Stats/ScanInfo-2.xml', 10),
    ])
    def test_reason_num_services(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_num_services()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 'services'),
        ('testdata/Stats/ScanInfo-2.xml', 'services'),
    ])
    def test_reason_services(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_services()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ScanInfo-3.xml'])
    def test_error_on_missing_reason_ttl(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ScanInfo-4.xml'])
    def test_error_on_missing_reason(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ScanInfo-5.xml'])
    def test_error_on_missing_state(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ScanInfo-6.xml'])
    def test_error_on_missing_state(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/ScanInfo-1.xml', 'testdata/Stats/ScanInfo-2.xml', False),
        ('testdata/Stats/ScanInfo-1.xml', 'testdata/Stats/ScanInfo-1.xml', True),
        ('testdata/Stats/ScanInfo-2.xml', 'testdata/Stats/ScanInfo-1.xml', False),
        ('testdata/Stats/ScanInfo-2.xml', 'testdata/Stats/ScanInfo-2.xml', True),
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

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_from_dict(self):
        pass

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_dict_to_xml(self):
        pass
