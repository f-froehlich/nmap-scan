import pytest

from nmap_scan.Host.Port import Port
from nmap_scan.Host.Service import Service
from nmap_scan.Stats.State import State
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestPort(BaseXMLTest):

    def create_instance(self, xml):
        return Port(xml)

    def get_all_files(self):
        return ['testdata/Host/Port-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Host/Port-13.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-1.xml', 22),
        ('testdata/Host/Port-2.xml', 22),
    ])
    def test_port(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_port()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-1.xml', 'testdata/Stats/State-1.xml'),
        ('testdata/Host/Port-2.xml', 'testdata/Stats/State-1.xml'),
    ])
    def test_state(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        state_xml = self.create_xml(expected)
        state = State(state_xml)
        assert state.equals(e.get_state())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-1.xml', 'testdata/Host/Service-3.xml'),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Service-7.xml'),
    ])
    def test_service(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        service_xml = self.create_xml(expected)
        service = Service(service_xml)
        assert service.equals(e.get_service())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-1.xml', 'tcp'),
        ('testdata/Host/Port-2.xml', 'tcp'),
    ])
    def test_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_protocol()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-1.xml', 'owner'),
        ('testdata/Host/Port-2.xml', 'owner'),
    ])
    def test_owner(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_owner()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', True),
        ('testdata/Host/Port-7.xml', True),
        ('testdata/Host/Port-8.xml', False),
    ])
    def test_open(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_open()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', True),
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', True),
    ])
    def test_closed(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_closed()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', True),
        ('testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', True),
        ('testdata/Host/Port-8.xml', True),
    ])
    def test_filtered(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_filtered()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', True),
        ('testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', False),
    ])
    def test_unfiltered(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_unfiltered()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', True),
        ('testdata/Host/Port-8.xml', False),
    ])
    def test_open_filtered(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_open_filtered()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', True),
    ])
    def test_closed_filtered(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_closed_filtered()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-6.xml', True),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', False),
        ('testdata/Host/Port-9.xml', False),
    ])
    def test_tcp_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_tcp_protocol()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', True),
        ('testdata/Host/Port-8.xml', False),
        ('testdata/Host/Port-9.xml', False),
    ])
    def test_ip_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_ip_protocol()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', False),
        ('testdata/Host/Port-9.xml', True),
    ])
    def test_udp_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_udp_protocol()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Port-6.xml', False),
        ('testdata/Host/Port-7.xml', False),
        ('testdata/Host/Port-8.xml', True),
        ('testdata/Host/Port-9.xml', False),
    ])
    def test_sctp_protocol(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_sctp_protocol()

    @pytest.mark.parametrize(("filepath", "script", "expected"), [
        ('testdata/Host/Port-1.xml', 'unknownId', True),
        ('testdata/Host/Port-1.xml', 'unknownId2', False),
    ])
    def test_has_script(self, filepath, script, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.has_script(script)
        if expected:
            assert script == e.get_script(script).get_id()
        else:
            assert None == e.get_script(script)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-1.xml', True),
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-2.xml', False),
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-1.xml', 'testdata/Host/Port-6.xml', False),

        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-1.xml', False),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-2.xml', True),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-2.xml', 'testdata/Host/Port-6.xml', False),

        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-1.xml', False),
        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-2.xml', False),
        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-3.xml', True),
        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-3.xml', 'testdata/Host/Port-6.xml', False),

        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-1.xml', False),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-2.xml', False),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-4.xml', True),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-6.xml', False),

        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-1.xml', False),
        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-2.xml', False),
        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-5.xml', True),
        ('testdata/Host/Port-5.xml', 'testdata/Host/Port-6.xml', False),

        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-1.xml', False),
        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-2.xml', False),
        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-3.xml', False),
        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-5.xml', False),
        ('testdata/Host/Port-6.xml', 'testdata/Host/Port-6.xml', True),

        ('testdata/Host/Port-9.xml', 'testdata/Host/Port-10.xml', False),
        ('testdata/Host/Port-10.xml', 'testdata/Host/Port-9.xml', False),
        ('testdata/Host/Port-4.xml', 'testdata/Host/Port-11.xml', False),
        ('testdata/Host/Port-11.xml', 'testdata/Host/Port-4.xml', False),
        ('testdata/Host/Port-11.xml', 'testdata/Host/Port-12.xml', False),
        ('testdata/Host/Port-12.xml', 'testdata/Host/Port-11.xml', False),
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
