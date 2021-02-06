import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.ExtraPort import ExtraPort
from nmap_scan.Stats.ExtraReason import ExtraReason
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.extraPort
class TestExtraPort(BaseXMLTest):

    def create_instance(self, xml):
        return ExtraPort(xml)

    def get_all_files(self):
        return ['testdata/Stats/ExtraPort-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/ExtraPort-' + str(i) + '.xml' for i in range(3, 5)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraPort-1.xml', 'state'),
        ('testdata/Stats/ExtraPort-2.xml', 'state'),
    ])
    def test_state(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_state()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraPort-1.xml', 10),
        ('testdata/Stats/ExtraPort-2.xml', 10),
    ])
    def test_count(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_count()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/ExtraPort-1.xml', ['testdata/Stats/ExtraReason-1.xml', 'testdata/Stats/ExtraReason-2.xml']),
        ('testdata/Stats/ExtraPort-2.xml', ['testdata/Stats/ExtraReason-2.xml', 'testdata/Stats/ExtraReason-5.xml']),
    ])
    def test_count(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        all_reasons = []
        for er in expected:
            xml = self.create_xml(er)
            all_reasons.append(ExtraReason(xml))

        assert len(all_reasons) == len(e.get_reasons())

        for a in all_reasons:
            exist = False
            for r in e.get_reasons():
                if r.equals(a):
                    assert not exist
                    exist = True

            assert exist

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ExtraPort-3.xml'])
    def test_error_on_missing_count(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/ExtraPort-4.xml'])
    def test_error_on_missing_state(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/ExtraPort-1.xml', 'testdata/Stats/ExtraPort-1.xml', True),
        ('testdata/Stats/ExtraPort-1.xml', 'testdata/Stats/ExtraPort-2.xml', False),
        ('testdata/Stats/ExtraPort-1.xml', 'testdata/Stats/ExtraPort-5.xml', False),
        ('testdata/Stats/ExtraPort-2.xml', 'testdata/Stats/ExtraPort-1.xml', False),
        ('testdata/Stats/ExtraPort-2.xml', 'testdata/Stats/ExtraPort-2.xml', True),
        ('testdata/Stats/ExtraPort-5.xml', 'testdata/Stats/ExtraPort-1.xml', False),
        ('testdata/Stats/ExtraPort-5.xml', 'testdata/Stats/ExtraPort-2.xml', False),
        ('testdata/Stats/ExtraPort-5.xml', 'testdata/Stats/ExtraPort-5.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
