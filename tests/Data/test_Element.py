import pytest

from nmap_scan.Data.Element import Element
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.element
class TestElement(BaseXMLTest):

    def create_instance(self, xml):
        return Element(xml)

    def get_all_files(self):
        return ['testdata/Data/Element-1.xml', 'testdata/Data/Element-2.xml']

    @pytest.mark.parametrize("filepath", ['testdata/Data/Element-1.xml', 'testdata/Data/Element-2.xml'])
    def test_data(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'data' == e.get_data()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Element-1.xml'])
    def test_key_not_none(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'key' == e.get_key()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Element-2.xml'])
    def test_key_none(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert None == e.get_key()
