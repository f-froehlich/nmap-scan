import pytest

from nmap_scan.OS.OS import OS
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestOS(BaseXMLTest):

    def create_instance(self, xml):
        return OS(xml)

    def get_all_files(self):
        return ['testdata/OS/OS-' + str(i) + '.xml' for i in range(1, 7)]

    def get_all_invalid_files(self):
        return ['testdata/OS/OS-7.xml']

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-1.xml', True),
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-2.xml', False),
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-3.xml', False),
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-4.xml', False),
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-5.xml', False),
        ('testdata/OS/OS-1.xml', 'testdata/OS/OS-6.xml', False),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-1.xml', False),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-2.xml', True),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-3.xml', False),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-4.xml', False),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-5.xml', False),
        ('testdata/OS/OS-2.xml', 'testdata/OS/OS-6.xml', False),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-1.xml', False),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-2.xml', False),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-3.xml', True),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-4.xml', False),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-5.xml', False),
        ('testdata/OS/OS-3.xml', 'testdata/OS/OS-6.xml', False),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-1.xml', False),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-2.xml', False),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-3.xml', False),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-4.xml', True),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-5.xml', False),
        ('testdata/OS/OS-4.xml', 'testdata/OS/OS-6.xml', False),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-1.xml', False),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-2.xml', False),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-3.xml', False),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-4.xml', False),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-5.xml', True),
        ('testdata/OS/OS-5.xml', 'testdata/OS/OS-6.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-1.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-2.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-3.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-4.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-5.xml', False),
        ('testdata/OS/OS-6.xml', 'testdata/OS/OS-6.xml', True),
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

    def test_equals_wrong_instance(self):
        xml1 = self.create_xml('testdata/OS/OS-1.xml')
        e1 = self.create_instance(xml1)

        assert not e1.equals('foo')

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_from_dict(self):
        pass

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_dict_to_xml(self):
        pass
