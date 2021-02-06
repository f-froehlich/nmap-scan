import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Sequence.TCPSequence import TCPSequence
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.sequence
class TestTCPSequence(BaseXMLTest):

    def create_instance(self, xml):
        return TCPSequence(xml)

    def get_all_files(self):
        return ['testdata/Sequence/TCPSequence-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Sequence/TCPSequence-5.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/TCPSequence-1.xml', 1),
        ('testdata/Sequence/TCPSequence-2.xml', 2),
    ])
    def test_index(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_index()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/TCPSequence-1.xml', 'difficulty'),
        ('testdata/Sequence/TCPSequence-2.xml', 'difficulty'),
    ])
    def test_difficulty(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_difficulty()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/TCPSequence-1.xml', 'values'),
        ('testdata/Sequence/TCPSequence-2.xml', 'values'),
    ])
    def test_values(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_values()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/TCPSequence-5.xml'])
    def test_error_on_missing_values(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/TCPSequence-4.xml'])
    def test_error_on_missing_difficulty(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/TCPSequence-3.xml'])
    def test_error_on_missing_index(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Sequence/TCPSequence-1.xml', 'testdata/Sequence/TCPSequence-2.xml', False),
        ('testdata/Sequence/TCPSequence-1.xml', 'testdata/Sequence/TCPSequence-1.xml', True),
        ('testdata/Sequence/TCPSequence-2.xml', 'testdata/Sequence/TCPSequence-1.xml', False),
        ('testdata/Sequence/TCPSequence-2.xml', 'testdata/Sequence/TCPSequence-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
