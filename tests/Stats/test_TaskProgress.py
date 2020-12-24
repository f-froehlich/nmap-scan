import pytest

from nmap_scan.Stats.TaskProgress import TaskProgress
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.hop
@pytest.mark.trace
class TestTaskProgress(BaseXMLTest):

    def create_instance(self, xml):
        return TaskProgress(xml)

    def get_all_files(self):
        return ['testdata/Stats/TaskProgress-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', 'task1'),
        ('testdata/Stats/TaskProgress-2.xml', 'task2'),
    ])
    def test_task(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_task()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', 10),
        ('testdata/Stats/TaskProgress-2.xml', 10),
    ])
    def test_time(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_time()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', 20),
        ('testdata/Stats/TaskProgress-2.xml', 20),
    ])
    def test_percent(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_percent()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', "30"),
        ('testdata/Stats/TaskProgress-2.xml', "30"),
    ])
    def test_remaining(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_remaining()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', "50"),
        ('testdata/Stats/TaskProgress-2.xml', "50"),
    ])
    def test_etc(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_etc()

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskProgress-3.xml'])
    def test_error_on_missing_etc(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "etc" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskProgress-4.xml'])
    def test_error_on_missing_remaining(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "remaining" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskProgress-5.xml'])
    def test_error_on_missing_percent(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "percent" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskProgress-6.xml'])
    def test_error_on_missing_time(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "time" in str(excinfo.value)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize("filepath", ['testdata/Stats/TaskProgress-7.xml'])
    def test_error_on_missing_task(self, filepath):
        with pytest.raises(KeyError) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
        assert "task" in str(excinfo.value)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Stats/TaskProgress-1.xml', 'testdata/Stats/TaskProgress-2.xml', False),
        ('testdata/Stats/TaskProgress-1.xml', 'testdata/Stats/TaskProgress-1.xml', True),
        ('testdata/Stats/TaskProgress-2.xml', 'testdata/Stats/TaskProgress-1.xml', False),
        ('testdata/Stats/TaskProgress-2.xml', 'testdata/Stats/TaskProgress-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
