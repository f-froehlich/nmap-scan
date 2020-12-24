import pytest

from nmap_scan.Sequence.IPIDSequence import IPIDSequence
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.sequence
class TestIPIDSequence(BaseXMLTest):

    def create_instance(self, xml):
        return IPIDSequence(xml)

    def get_all_files(self):
        return ['testdata/Sequence/IPIDSequence-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/IPIDSequence-1.xml', 'class'),
        ('testdata/Sequence/IPIDSequence-2.xml', 'class2'),
    ])
    def test_index(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_class()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Sequence/IPIDSequence-1.xml', 'values'),
        ('testdata/Sequence/IPIDSequence-2.xml', 'values'),
    ])
    def test_values(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_values()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/IPIDSequence-3.xml'])
    def test_error_on_missing_values(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "values" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Sequence/IPIDSequence-4.xml'])
    def test_error_on_missing_difficulty(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "class" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Sequence/IPIDSequence-1.xml', 'testdata/Sequence/IPIDSequence-2.xml', False),
        ('testdata/Sequence/IPIDSequence-1.xml', 'testdata/Sequence/IPIDSequence-1.xml', True),
        ('testdata/Sequence/IPIDSequence-2.xml', 'testdata/Sequence/IPIDSequence-1.xml', False),
        ('testdata/Sequence/IPIDSequence-2.xml', 'testdata/Sequence/IPIDSequence-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
