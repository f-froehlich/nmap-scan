import pytest

from nmap_scan.Host.Host import Host
from nmap_scan.Report.Report import Report
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Stats.Output import Output
from nmap_scan.Stats.RunStats import RunStats
from nmap_scan.Stats.ScanInfo import ScanInfo
from nmap_scan.Stats.Target import Target
from nmap_scan.Stats.TaskBegin import TaskBegin
from nmap_scan.Stats.TaskEnd import TaskEnd
from nmap_scan.Stats.TaskProgress import TaskProgress
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.report
class TestReport(BaseXMLTest):

    def create_instance(self, xml):
        c = self.get_class()
        return c(xml)

    def get_class(self):
        return Report

    def get_all_files(self):
        return ['testdata/Report/Report-' + str(i) + '.xml' for i in range(1, 2)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'nmap'),
    ])
    def test_scanner(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_scanner()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'profile_name'),
    ])
    def test_profile_name(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_profile_name()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', '1.05'),
    ])
    def test_xmloutputversion(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_xml_output_version()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', '7.91SVN'),
    ])
    def test_version(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_version()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'start'),
    ])
    def test_startstr(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_start_string()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 1607786410),
    ])
    def test_start(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_start()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'args'),
    ])
    def test_args(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_scanner_args()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 1),
    ])
    def test_verbose(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_verbose_level()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 2),
    ])
    def test_debug(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_debugging_level()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/ScanInfo-1.xml'),
    ])
    def test_scannerinfo(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = ScanInfo(self.create_xml(expected))

        assert 1 == len(e.get_scaninfos())
        assert expected_object.equals(e.get_scaninfos()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/Output-1.xml'),
    ])
    def test_outputs(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = Output(self.create_xml(expected))

        assert 1 == len(e.get_outputs())
        assert expected_object.equals(e.get_outputs()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/TaskProgress-1.xml'),
    ])
    def test_task_progress(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = TaskProgress(self.create_xml(expected))

        assert 1 == len(e.get_task_progresses())
        assert expected_object.equals(e.get_task_progresses()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/TaskBegin-1.xml'),
    ])
    def test_task_begin(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = TaskBegin(self.create_xml(expected))

        assert 1 == len(e.get_task_begins())
        assert expected_object.equals(e.get_task_begins()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/TaskEnd-1.xml'),
    ])
    def test_task_end(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = TaskEnd(self.create_xml(expected))

        assert 1 == len(e.get_task_ends())
        assert expected_object.equals(e.get_task_ends()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/RunStats-1.xml'),
    ])
    def test_run_stats(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = RunStats(self.create_xml(expected))

        assert expected_object.equals(e.get_run_stats())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Stats/Target-1.xml'),
    ])
    def test_targets(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_object = Target(self.create_xml(expected))

        assert 1 == len(e.get_targets())
        assert expected_object.equals(e.get_targets()[0])

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Host/Host-1.xml', 'testdata/Host/Host-2.xml', 'testdata/Host/Host-3.xml',
          'testdata/Host/Host-4.xml']),
    ])
    def test_hosts(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(Host(self.create_xml(ex)))

        assert len(expected) == len(e.get_hosts())
        assert len(expected) == len(e.get_hosts_with_port([22]))
        assert len(expected) == len(e.get_host_with_port(22))
        assert len(expected) == len(e.get_hosts_with_script('unknownId'))
        for ex in expected_objects:
            exist = False
            for c in e.get_hosts():
                if ex.equals(c):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Host/Host-1.xml']),
    ])
    def test_hosts_up(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(Host(self.create_xml(ex)))
        hosts = e.get_hosts_up()
        assert len(expected) == len(hosts)
        assert len(expected) == len(e.get_hosts_up_with_port([22]))
        assert hosts == e.get_hosts_up()
        for ex in expected_objects:
            exist = False
            for c in e.get_hosts_up():
                if ex.equals(c):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Host/Host-2.xml']),
    ])
    def test_hosts_down(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(Host(self.create_xml(ex)))
        hosts = e.get_hosts_down()
        assert len(expected) == len(hosts)
        assert len(expected) == len(e.get_hosts_down_with_port([22]))
        assert hosts == e.get_hosts_down()
        for ex in expected_objects:
            exist = False
            for c in e.get_hosts_down():
                if ex.equals(c):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Host/Host-3.xml']),
    ])
    def test_hosts_unknown(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(Host(self.create_xml(ex)))
        hosts = e.get_hosts_unknown()
        assert len(expected) == len(hosts)
        assert len(expected) == len(e.get_hosts_unknown_with_port([22]))
        assert hosts == e.get_hosts_unknown()
        for ex in expected_objects:
            exist = False
            for c in e.get_hosts_unknown():
                if ex.equals(c):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Host/Host-4.xml']),
    ])
    def test_hosts_skipped(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(Host(self.create_xml(ex)))
        hosts = e.get_hosts_skipped()
        assert len(expected) == len(hosts)
        assert len(expected) == len(e.get_hosts_skipped_with_port([22]))
        assert hosts == e.get_hosts_skipped()
        for ex in expected_objects:
            exist = False
            for c in e.get_hosts_skipped():
                if ex.equals(c):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Scripts/UnknownScript-1.xml']),
    ])
    def test_pre_script(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(parse(self.create_xml(ex)))
        hosts = e.get_pre_scripts()
        assert len(expected) == len(hosts)
        for ex in expected_objects:
            assert e.has_post_script(ex.get_id())
            assert ex.equals(e.get_pre_script(ex.get_id()))
            exist = False
            for c in e.get_pre_scripts():
                if ex.equals(e.get_pre_scripts()[c]):
                    exist = True
                    break
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Report/Report-1.xml',
         ['testdata/Scripts/UnknownScript-1.xml']),
    ])
    def test_post_script(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        expected_objects = []
        for ex in expected:
            expected_objects.append(parse(self.create_xml(ex)))
        hosts = e.get_post_scripts()
        assert len(expected) == len(hosts)
        for ex in expected_objects:
            assert e.has_pre_script(ex.get_id())
            assert ex.equals(e.get_post_script(ex.get_id()))
            exist = False
            for c in e.get_post_scripts():
                if ex.equals(e.get_post_scripts()[c]):
                    exist = True
                    break
            assert exist

    @pytest.mark.xml
    def test_save_and_load(self):
        for filepath in self.get_all_files():
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)
            e.save('.testreport.xml')
            assert self.get_class().from_file('.testreport.xml').equals(e)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Report/Report-1.xml', 'testdata/Report/Report-1.xml', True),

    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
