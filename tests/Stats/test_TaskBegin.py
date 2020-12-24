import pytest

from nmap_scan.Stats.TaskBegin import TaskBegin
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.task
@pytest.mark.taskBegin
class TestTaskBegin(BaseXMLTest):

    def create_instance(self, xml):
        return TaskBegin(xml)

    def get_all_files(self):
        return ['testdata/Stats/TaskBegin-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskBegin-1.xml', 'task1'),
        ('testdata/Stats/TaskBegin-2.xml', 'task2'),
    ])
    def test_task(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_task()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskBegin-1.xml', '10'),
        ('testdata/Stats/TaskBegin-2.xml', '10'),
    ])
    def test_time(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_time()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskBegin-1.xml', 'foo'),
        ('testdata/Stats/TaskBegin-2.xml', None),
    ])
    def test_extra_info(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_extra_info()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskBegin-3.xml'])
    def test_error_on_missing_time(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "time" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskBegin-4.xml'])
    def test_error_on_missing_task(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "task" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/TaskBegin-1.xml', 'testdata/Stats/TaskBegin-2.xml', False),
        ('testdata/Stats/TaskBegin-1.xml', 'testdata/Stats/TaskBegin-1.xml', True),
        ('testdata/Stats/TaskBegin-2.xml', 'testdata/Stats/TaskBegin-1.xml', False),
        ('testdata/Stats/TaskBegin-2.xml', 'testdata/Stats/TaskBegin-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
