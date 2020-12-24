from xml.etree.ElementTree import Element as XMLElement

import pytest

from nmap_scan.Data.Element import Element
from nmap_scan.Data.Table import Table
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestUnknownScript(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/UnknownScript-' + str(i) + '.xml' for i in range(1, 6)]

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-' + str(i) + '.xml' for i in range(1, 6)])
    def test_id(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'unknownId' == e.get_id()

    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-' + str(i) + '.xml' for i in range(1, 6)])
    def test_output(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'scriptOutput' == e.get_output()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-6.xml'])
    def test_key_error_on_missing_id(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "id" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-7.xml'])
    def test_key_error_on_missing_output(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "output" in str(excinfo.value)

    @pytest.mark.table
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-2.xml'])
    def test_can_create_table(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 1 == len(e.get_tables())
        assert 0 == len(e.get_elements())
        assert 0 == len(e.get_data())

        assert isinstance(e.get_tables()[0], Table)
        assert 'table1' == e.get_tables()[0].get_key()

    @pytest.mark.element
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-3.xml'])
    def test_can_create_element(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 0 == len(e.get_tables())
        assert 1 == len(e.get_elements())
        assert 0 == len(e.get_data())

        assert isinstance(e.get_elements()[0], Element)
        assert 'element1' == e.get_elements()[0].get_key()

    @pytest.mark.element
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-4.xml'])
    def test_can_create_data(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 0 == len(e.get_tables())
        assert 0 == len(e.get_elements())
        assert 1 == len(e.get_data())

        assert isinstance(e.get_data()[0], XMLElement)
        assert 'foo' == e.get_data()[0].tag
        assert 'ParseAsXMLElement' == e.get_data()[0].text

    @pytest.mark.element
    @pytest.mark.parametrize("filepath", ['testdata/Scripts/UnknownScript-5.xml'])
    def test_can_create_all(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 1 == len(e.get_tables())
        assert 1 == len(e.get_elements())
        assert 1 == len(e.get_data())

        assert isinstance(e.get_tables()[0], Table)
        assert 'table1' == e.get_tables()[0].get_key()

        assert isinstance(e.get_elements()[0], Element)
        assert 'element1' == e.get_elements()[0].get_key()

        assert isinstance(e.get_data()[0], XMLElement)
        assert 'foo' == e.get_data()[0].tag
        assert 'ParseAsXMLElement' == e.get_data()[0].text
