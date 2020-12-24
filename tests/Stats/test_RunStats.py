import pytest

from nmap_scan.Stats.RunStats import RunStats
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.runstats
class TestRunStats(BaseXMLTest):

    def create_instance(self, xml):
        return RunStats(xml)

    def get_all_files(self):
        return ['testdata/Stats/RunStats-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 10),
        ('testdata/Stats/RunStats-2.xml', 20),
    ])
    def test_time(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_time()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 2),
        ('testdata/Stats/RunStats-2.xml', 2),
    ])
    def test_up(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_up()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 0),
        ('testdata/Stats/RunStats-2.xml', 0),
    ])
    def test_down(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_down()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 2),
        ('testdata/Stats/RunStats-2.xml', 2),
    ])
    def test_total(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_total()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 'success'),
        ('testdata/Stats/RunStats-2.xml', 'success'),
    ])
    def test_exit(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_exit()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 10.5),
        ('testdata/Stats/RunStats-2.xml', 10.5),
    ])
    def test_elapsed(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_elapsed()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 'summary'),
        ('testdata/Stats/RunStats-2.xml', 'summary'),
    ])
    def test_summary(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_summary()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 'timestr'),
        ('testdata/Stats/RunStats-2.xml', 'timestr'),
    ])
    def test_time_str(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_time_string()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/RunStats-3.xml'])
    def test_error_on_missing_reason_ttl(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "time" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/RunStats-1.xml', 'testdata/Stats/RunStats-2.xml', False),
        ('testdata/Stats/RunStats-1.xml', 'testdata/Stats/RunStats-1.xml', True),
        ('testdata/Stats/RunStats-2.xml', 'testdata/Stats/RunStats-1.xml', False),
        ('testdata/Stats/RunStats-2.xml', 'testdata/Stats/RunStats-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
