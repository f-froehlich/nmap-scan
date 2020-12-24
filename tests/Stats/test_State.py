import pytest

from nmap_scan.Stats.State import State
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.state
class TestState(BaseXMLTest):

    def create_instance(self, xml):
        return State(xml)

    def get_all_files(self):
        return ['testdata/Stats/State-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/State-1.xml', 'up'),
        ('testdata/Stats/State-2.xml', 'up'),
    ])
    def test_state(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_state()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/State-1.xml', 'reason'),
        ('testdata/Stats/State-2.xml', 'reason'),
    ])
    def test_reason(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/State-1.xml', 10),
        ('testdata/Stats/State-2.xml', 10),
    ])
    def test_reason_ttl(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason_ttl()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/State-1.xml', 'ip'),
        ('testdata/Stats/State-2.xml', 'ip2'),
    ])
    def test_reason_ip(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_reason_ip()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/State-3.xml'])
    def test_error_on_missing_reason_ttl(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "reason_ttl" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/State-4.xml'])
    def test_error_on_missing_reason(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "reason" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/State-5.xml'])
    def test_error_on_missing_state(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "state" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/State-1.xml', 'testdata/Stats/State-2.xml', False),
        ('testdata/Stats/State-1.xml', 'testdata/Stats/State-1.xml', True),
        ('testdata/Stats/State-2.xml', 'testdata/Stats/State-1.xml', False),
        ('testdata/Stats/State-2.xml', 'testdata/Stats/State-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
