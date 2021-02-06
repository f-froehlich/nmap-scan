import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Stats.TaskEnd import TaskEnd
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.task
@pytest.mark.taskEnd
class TestTaskEnd(BaseXMLTest):

    def create_instance(self, xml):
        return TaskEnd(xml)

    def get_all_files(self):
        return ['testdata/Stats/TaskEnd-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Stats/TaskEnd-' + str(i) + '.xml' for i in range(3, 5)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskEnd-1.xml', 'task1'),
        ('testdata/Stats/TaskEnd-2.xml', 'task2'),
    ])
    def test_task(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_task()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskEnd-1.xml', '10'),
        ('testdata/Stats/TaskEnd-2.xml', '10'),
    ])
    def test_time(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_time()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskEnd-1.xml', 'foo'),
        ('testdata/Stats/TaskEnd-2.xml', None),
    ])
    def test_extra_info(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_extra_info()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskEnd-3.xml'])
    def test_error_on_missing_time(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskEnd-4.xml'])
    def test_error_on_missing_task(self, filepath):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/TaskEnd-1.xml', 'testdata/Stats/TaskEnd-2.xml', False),
        ('testdata/Stats/TaskEnd-1.xml', 'testdata/Stats/TaskEnd-1.xml', True),
        ('testdata/Stats/TaskEnd-2.xml', 'testdata/Stats/TaskEnd-1.xml', False),
        ('testdata/Stats/TaskEnd-2.xml', 'testdata/Stats/TaskEnd-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
