import pytest

from nmap_scan.Stats.Time import Time
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.time
class TestTime(BaseXMLTest):

    def create_instance(self, xml):
        return Time(xml)

    def get_all_files(self):
        return ['testdata/Stats/Time-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Time-1.xml', "srtt"),
        ('testdata/Stats/Time-2.xml', "srtt2"),
    ])
    def test_srtt(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_srtt()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Time-1.xml', "rttvar"),
        ('testdata/Stats/Time-2.xml', "rttvar2"),
    ])
    def test_rttvar(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_rttvar()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/Time-1.xml', "to"),
        ('testdata/Stats/Time-2.xml', "to2"),
    ])
    def test_to(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_to()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Time-3.xml'])
    def test_error_on_missing_to(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "to" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Time-4.xml'])
    def test_error_on_missing_rttvar(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "rttvar" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/Time-5.xml'])
    def test_error_on_missing_srtt(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "srtt" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/Time-1.xml', 'testdata/Stats/Time-2.xml', False),
        ('testdata/Stats/Time-1.xml', 'testdata/Stats/Time-1.xml', True),
        ('testdata/Stats/Time-2.xml', 'testdata/Stats/Time-1.xml', False),
        ('testdata/Stats/Time-2.xml', 'testdata/Stats/Time-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
