import pytest

from nmap_scan.Stats.Target import Target
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.target
class TestTarget(BaseXMLTest):

    def create_instance(self, xml):
        return Target(xml)

    def get_all_files(self):
        return ['testdata/Stats/Target-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Target-1.xml', 'specification'),
        ('testdata/Stats/Target-2.xml', 'specification'),
    ])
    def test_specification(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_specification()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Target-1.xml', 'status'),
        ('testdata/Stats/Target-2.xml', None),
    ])
    def test_status(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_status()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Target-1.xml', 'reason'),
        ('testdata/Stats/Target-2.xml', None),
    ])
    def test_reason(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Target-3.xml'])
    def test_error_on_missing_time(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "specification" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/Target-1.xml', 'testdata/Stats/Target-2.xml', False),
        ('testdata/Stats/Target-1.xml', 'testdata/Stats/Target-1.xml', True),
        ('testdata/Stats/Target-2.xml', 'testdata/Stats/Target-1.xml', False),
        ('testdata/Stats/Target-2.xml', 'testdata/Stats/Target-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
