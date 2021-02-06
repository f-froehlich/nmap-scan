import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.Status import Status
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.status
class TestStatus(BaseXMLTest):

    def create_instance(self, xml):
        return Status(xml)

    def get_all_files(self):
        return ['testdata/Stats/Status-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/Status-' + str(i) + '.xml' for i in range(3, 6)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Status-1.xml', 'up'),
        ('testdata/Stats/Status-2.xml', 'down'),
    ])
    def test_state(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_state()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Status-1.xml', 'reason'),
        ('testdata/Stats/Status-2.xml', 'reason'),
    ])
    def test_reason(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Status-1.xml', 10),
        ('testdata/Stats/Status-2.xml', 10),
    ])
    def test_reason_ttl(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason_ttl()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Status-3.xml'])
    def test_error_on_missing_reason_ttl(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Status-4.xml'])
    def test_error_on_missing_reason(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Status-5.xml'])
    def test_error_on_missing_state(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/Status-1.xml', 'testdata/Stats/Status-2.xml', False),
        ('testdata/Stats/Status-1.xml', 'testdata/Stats/Status-1.xml', True),
        ('testdata/Stats/Status-2.xml', 'testdata/Stats/Status-1.xml', False),
        ('testdata/Stats/Status-2.xml', 'testdata/Stats/Status-2.xml', True),
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
