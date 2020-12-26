import pytest
from lxml import etree

from nmap_scan.Data.Element import Element
from nmap_scan.Data.Table import Table
from nmap_scan.Scripts.ScriptParser import parse
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
class TestUnknownScript(BaseXMLTest):

    def create_instance(self, xml):
        return parse(xml)

    def get_all_files(self):
        return ['testdata/Scripts/UnknownScript-' + str(i) + '.xml' for i in range(1, 14) if i not in [6, 7]]

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

        assert isinstance(e.get_data()[0], etree._Element)
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

        assert isinstance(e.get_data()[0], etree._Element)
        assert 'foo' == e.get_data()[0].tag
        assert 'ParseAsXMLElement' == e.get_data()[0].text

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-1.xml', True),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-1.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-2.xml', True),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-2.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-3.xml', True),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-3.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-4.xml', True),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-4.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-5.xml', True),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-5.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-8.xml', True),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-8.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-9.xml', True),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-9.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-10.xml', True),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-10.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-11.xml', True),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-11.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-12.xml', True),
        ('testdata/Scripts/UnknownScript-12.xml', 'testdata/Scripts/UnknownScript-13.xml', False),

        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-1.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-2.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-3.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-4.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-5.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-8.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-9.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-10.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-11.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-12.xml', False),
        ('testdata/Scripts/UnknownScript-13.xml', 'testdata/Scripts/UnknownScript-13.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
