import pytest

from nmap_scan.Trace.Hop import Hop
from nmap_scan.Trace.Trace import Trace
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.trace
class TestHop(BaseXMLTest):

    def create_instance(self, xml):
        return Trace(xml)

    def get_all_files(self):
        return ['testdata/Trace/Trace-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Trace-1.xml', 'tcp'),
        ('testdata/Trace/Trace-2.xml', None),
    ])
    def test_proto(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_proto()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Trace/Trace-1.xml', 10),
        ('testdata/Trace/Trace-2.xml', None),
    ])
    def test_port(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_port()

    @pytest.mark.hop
    @pytest.mark.parametrize(("filepath", "hops"), [
        ('testdata/Trace/Trace-1.xml', ['testdata/Trace/Hop-1.xml']),
        ('testdata/Trace/Trace-2.xml', []),
    ])
    def test_hops(self, filepath, hops):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        expected_hops = []
        for h in hops:
            xml = self.create_xml(h)
            expected_hops.append(Hop(xml))

        assert len(expected_hops) == len(e.get_hops())

        for expected in expected_hops:
            exist = False
            for h in e.get_hops():
                if expected.equals(h):
                    assert not exist
                    exist = True
            assert exist

    @pytest.mark.hop
    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Trace/Trace-1.xml', 'testdata/Trace/Trace-1.xml', True),
        ('testdata/Trace/Trace-1.xml', 'testdata/Trace/Trace-2.xml', False),
        ('testdata/Trace/Trace-1.xml', 'testdata/Trace/Trace-3.xml', False),
        ('testdata/Trace/Trace-1.xml', 'testdata/Trace/Trace-4.xml', False),
        ('testdata/Trace/Trace-1.xml', 'testdata/Trace/Trace-5.xml', False),
        ('testdata/Trace/Trace-2.xml', 'testdata/Trace/Trace-1.xml', False),
        ('testdata/Trace/Trace-2.xml', 'testdata/Trace/Trace-2.xml', True),
        ('testdata/Trace/Trace-2.xml', 'testdata/Trace/Trace-3.xml', False),
        ('testdata/Trace/Trace-2.xml', 'testdata/Trace/Trace-4.xml', False),
        ('testdata/Trace/Trace-2.xml', 'testdata/Trace/Trace-5.xml', False),
        ('testdata/Trace/Trace-3.xml', 'testdata/Trace/Trace-1.xml', False),
        ('testdata/Trace/Trace-3.xml', 'testdata/Trace/Trace-2.xml', False),
        ('testdata/Trace/Trace-3.xml', 'testdata/Trace/Trace-3.xml', True),
        ('testdata/Trace/Trace-3.xml', 'testdata/Trace/Trace-4.xml', False),
        ('testdata/Trace/Trace-3.xml', 'testdata/Trace/Trace-5.xml', False),
        ('testdata/Trace/Trace-4.xml', 'testdata/Trace/Trace-1.xml', False),
        ('testdata/Trace/Trace-4.xml', 'testdata/Trace/Trace-2.xml', False),
        ('testdata/Trace/Trace-4.xml', 'testdata/Trace/Trace-3.xml', False),
        ('testdata/Trace/Trace-4.xml', 'testdata/Trace/Trace-4.xml', True),
        ('testdata/Trace/Trace-4.xml', 'testdata/Trace/Trace-5.xml', False),
        ('testdata/Trace/Trace-5.xml', 'testdata/Trace/Trace-1.xml', False),
        ('testdata/Trace/Trace-5.xml', 'testdata/Trace/Trace-2.xml', False),
        ('testdata/Trace/Trace-5.xml', 'testdata/Trace/Trace-3.xml', False),
        ('testdata/Trace/Trace-5.xml', 'testdata/Trace/Trace-4.xml', False),
        ('testdata/Trace/Trace-5.xml', 'testdata/Trace/Trace-5.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
