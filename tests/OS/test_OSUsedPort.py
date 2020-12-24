import pytest

from nmap_scan.OS.OSUsedPort import OSUsedPort
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestOSUsedPort(BaseXMLTest):

    def create_instance(self, xml):
        return OSUsedPort(xml)

    def get_all_files(self):
        return ['testdata/OS/OSUsedPort-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSUsedPort-1.xml', 'up'),
        ('testdata/OS/OSUsedPort-2.xml', 'down'),
    ])
    def test_state(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_state()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSUsedPort-1.xml', 22),
        ('testdata/OS/OSUsedPort-2.xml', 22),
    ])
    def test_port(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_port()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/OS/OSUsedPort-1.xml', 'tcp'),
        ('testdata/OS/OSUsedPort-2.xml', 'tcp'),
    ])
    def test_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_proto()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize(("filepath", "expected_error"), [
        ('testdata/OS/OSUsedPort-3.xml', 'portid'),
        ('testdata/OS/OSUsedPort-4.xml', 'proto'),
        ('testdata/OS/OSUsedPort-5.xml', 'state'),
    ])
    def test_error_on_missing_required_param(self, filepath, expected_error):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert expected_error in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/OS/OSUsedPort-1.xml', 'testdata/OS/OSUsedPort-1.xml', True),
        ('testdata/OS/OSUsedPort-1.xml', 'testdata/OS/OSUsedPort-2.xml', False),
        ('testdata/OS/OSUsedPort-2.xml', 'testdata/OS/OSUsedPort-1.xml', False),
        ('testdata/OS/OSUsedPort-2.xml', 'testdata/OS/OSUsedPort-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
