import pytest

from nmap_scan.Data.Element import Element
from nmap_scan.Data.Table import Table
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.table
class TestTable(BaseXMLTest):

    def create_instance(self, xml):
        return Table(xml)

    def get_all_files(self):
        return ['testdata/Data/Table-1.xml', 'testdata/Data/Table-2.xml', 'testdata/Data/Table-3.xml',
                'testdata/Data/Table-4.xml', 'testdata/Data/Table-5.xml']

    def get_all_invalid_files(self):
        return ['testdata/Data/Table-9.xml']

    @pytest.mark.parametrize("filepath",
                             ['testdata/Data/Table-1.xml', 'testdata/Data/Table-2.xml', 'testdata/Data/Table-3.xml',
                              'testdata/Data/Table-5.xml'])
    def test_key_not_none(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'key' == e.get_key()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Table-4.xml'])
    def test_key_none(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert None == e.get_key()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Table-3.xml'])
    def test_table_has_child_table(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'key' == e.get_key()
        assert 1 == len(e.get_tables())
        assert 0 == len(e.get_elements())

        assert isinstance(e.get_tables()[0], Table)
        assert 'child1' == e.get_tables()[0].get_key()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Table-2.xml'])
    def test_table_has_child_elements(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'key' == e.get_key()
        assert 0 == len(e.get_tables())
        assert 2 == len(e.get_elements())

        assert isinstance(e.get_elements()[0], Element)
        assert isinstance(e.get_elements()[1], Element)
        assert 'element1' == e.get_elements()[0].get_key()
        assert 'element2' == e.get_elements()[1].get_key()

    @pytest.mark.parametrize("filepath", ['testdata/Data/Table-1.xml'])
    def test_table_has_child_elements_and_table(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 'key' == e.get_key()
        assert 1 == len(e.get_tables())
        assert 2 == len(e.get_elements())

        assert isinstance(e.get_elements()[0], Element)
        assert isinstance(e.get_elements()[1], Element)
        assert 'element1' == e.get_elements()[0].get_key()
        assert 'element2' == e.get_elements()[1].get_key()

        assert isinstance(e.get_tables()[0], Table)
        assert 'child1' == e.get_tables()[0].get_key()

        assert 1 == len(e.get_tables()[0].get_elements())
        assert isinstance(e.get_tables()[0].get_elements()[0], Element)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-1.xml', True),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-1.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-2.xml', True),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-2.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-3.xml', True),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-3.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-4.xml', True),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-4.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-5.xml', True),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-5.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-6.xml', True),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-6.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-7.xml', True),
        ('testdata/Data/Table-7.xml', 'testdata/Data/Table-8.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-1.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-2.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-3.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-4.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-5.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-6.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-7.xml', False),
        ('testdata/Data/Table-8.xml', 'testdata/Data/Table-8.xml', True),

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

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_from_dict(self):
        pass

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_dict_to_xml(self):
        pass
