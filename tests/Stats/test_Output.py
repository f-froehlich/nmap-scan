import pytest

from nmap_scan.Stats.Output import Output
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.output
class TestOutput(BaseXMLTest):

    def create_instance(self, xml):
        return Output(xml)

    def get_all_files(self):
        return ['testdata/Stats/Output-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Output-1.xml', 'interactive'),
        ('testdata/Stats/Output-2.xml', 'bar'),
    ])
    def test_type(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Output-1.xml', 'foo'),
        ('testdata/Stats/Output-2.xml', 'bar'),
    ])
    def test_up(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_data()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/Output-1.xml', 'testdata/Stats/Output-2.xml', False),
        ('testdata/Stats/Output-1.xml', 'testdata/Stats/Output-1.xml', True),
        ('testdata/Stats/Output-2.xml', 'testdata/Stats/Output-1.xml', False),
        ('testdata/Stats/Output-2.xml', 'testdata/Stats/Output-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
