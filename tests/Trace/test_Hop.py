import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Trace.Hop import Hop
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.hop
@pytest.mark.trace
class TestHop(BaseXMLTest):

    def create_instance(self, xml):
        return Hop(xml)

    def get_all_files(self):
        return ['testdata/Trace/Hop-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Trace/Hop-' + str(i) + '.xml' for i in range(3, 4)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Hop-1.xml', 'ttl'),
        ('testdata/Trace/Hop-2.xml', 'ttl'),
    ])
    def test_ttl(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_ttl()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Hop-1.xml', 'rtt'),
        ('testdata/Trace/Hop-2.xml', None),
    ])
    def test_rtt(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_rtt()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Hop-1.xml', 'IP'),
        ('testdata/Trace/Hop-2.xml', None),
    ])
    def test_rtt(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_ip()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Hop-1.xml', 'host'),
        ('testdata/Trace/Hop-2.xml', None),
    ])
    def test_rtt(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_host()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Trace/Hop-1.xml', 'testdata/Trace/Hop-2.xml', False),
        ('testdata/Trace/Hop-1.xml', 'testdata/Trace/Hop-1.xml', True),
        ('testdata/Trace/Hop-2.xml', 'testdata/Trace/Hop-1.xml', False),
        ('testdata/Trace/Hop-2.xml', 'testdata/Trace/Hop-2.xml', True),
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
    @pytest.mark.parametrize("filepath", ['testdata/Trace/Hop-3.xml'])
    def test_key_error_on_missing_id(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
