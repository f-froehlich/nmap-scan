import pytest

from nmap_scan.OS.OSMatch import OSMatch
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestOSMatch(BaseXMLTest):

    def create_instance(self, xml):
        return OSMatch(xml)

    def get_all_files(self):
        return ['testdata/OS/OSMatch-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSMatch-1.xml', 'name'),
        ('testdata/OS/OSMatch-2.xml', 'name'),
    ])
    def test_name(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_name()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSMatch-1.xml', 44),
        ('testdata/OS/OSMatch-2.xml', 44),
    ])
    def test_accuracy(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_accuracy()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSMatch-1.xml', 55),
        ('testdata/OS/OSMatch-2.xml', 55),
    ])
    def test_line(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_line()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize(("filepath", "expected_error"), [
        ('testdata/OS/OSMatch-3.xml', 'line'),
        ('testdata/OS/OSMatch-4.xml', 'accuracy'),
        ('testdata/OS/OSMatch-5.xml', 'name'),
    ])
    def test_error_on_missing_required_param(self, filepath, expected_error):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert expected_error in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/OS/OSMatch-1.xml', 'testdata/OS/OSMatch-1.xml', True),
        ('testdata/OS/OSMatch-1.xml', 'testdata/OS/OSMatch-2.xml', False),
        ('testdata/OS/OSMatch-2.xml', 'testdata/OS/OSMatch-1.xml', False),
        ('testdata/OS/OSMatch-2.xml', 'testdata/OS/OSMatch-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
