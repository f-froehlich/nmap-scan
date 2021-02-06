import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Sequence.TCPTSSequence import TCPTSSequence
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.sequence
class TestTCPTSSequence(BaseXMLTest):

    def create_instance(self, xml):
        return TCPTSSequence(xml)

    def get_all_files(self):
        return ['testdata/Sequence/TCPTSSequence-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Sequence/TCPTSSequence-3.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/TCPTSSequence-1.xml', 'class'),
        ('testdata/Sequence/TCPTSSequence-2.xml', 'class2'),
    ])
    def test_index(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_class()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/TCPTSSequence-1.xml', 'values'),
        ('testdata/Sequence/TCPTSSequence-2.xml', 'values'),
    ])
    def test_values(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_values()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/TCPTSSequence-3.xml'])
    def test_error_on_missing_difficulty(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Sequence/TCPTSSequence-1.xml', 'testdata/Sequence/TCPTSSequence-2.xml', False),
        ('testdata/Sequence/TCPTSSequence-1.xml', 'testdata/Sequence/TCPTSSequence-1.xml', True),
        ('testdata/Sequence/TCPTSSequence-2.xml', 'testdata/Sequence/TCPTSSequence-1.xml', False),
        ('testdata/Sequence/TCPTSSequence-2.xml', 'testdata/Sequence/TCPTSSequence-2.xml', True),
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
