import pytest

from nmap_scan.Host.Host import Host
from nmap_scan.Host.HostAddress import HostAddress
from nmap_scan.Scripts.ScriptParser import parse
from nmap_scan.Sequence.IPIDSequence import IPIDSequence
from nmap_scan.Sequence.TCPSequence import TCPSequence
from nmap_scan.Sequence.TCPTSSequence import TCPTSSequence
from nmap_scan.Stats.Status import Status
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestHost(BaseXMLTest):

    def create_instance(self, xml):
        return Host(xml)

    def get_all_files(self):
        return ['testdata/Host/Host-' + str(i) + '.xml' for i in range(1, 3)]

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 'testdata/Stats/Status-1.xml'),
    ])
    def test_status(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        state_xml = self.create_xml(expected)
        state = Status(state_xml)
        assert state.equals(e.get_status())

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', True),
        ('testdata/Host/Host-2.xml', False),
        ('testdata/Host/Host-3.xml', False),
        ('testdata/Host/Host-4.xml', False),
    ])
    def test_is_up(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_up()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', False),
        ('testdata/Host/Host-2.xml', True),
        ('testdata/Host/Host-3.xml', False),
        ('testdata/Host/Host-4.xml', False),
    ])
    def test_is_down(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_down()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', False),
        ('testdata/Host/Host-2.xml', False),
        ('testdata/Host/Host-3.xml', True),
        ('testdata/Host/Host-4.xml', False),
    ])
    def test_is_unknown(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_unknown()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', False),
        ('testdata/Host/Host-2.xml', False),
        ('testdata/Host/Host-3.xml', False),
        ('testdata/Host/Host-4.xml', True),
    ])
    def test_is_skipped(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.is_skipped()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 'testdata/Host/HostAddress-1.xml'),
    ])
    def test_address(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        state_xml = self.create_xml(expected)
        state = HostAddress(state_xml)
        exist = False
        for a in e.get_addresses():
            if a.equals(state):
                exist = True

        assert exist

    @pytest.mark.parametrize(("filepath", "ip", "expected"), [
        ('testdata/Host/Host-1.xml', "address", True),
        ('testdata/Host/Host-1.xml', "address6", False),
    ])
    def test_has_ipv4(self, filepath, ip, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.has_ipv4(ip)
        assert expected == e.has_ip(ip)

    @pytest.mark.parametrize(("filepath", "ip", "expected"), [
        ('testdata/Host/Host-2.xml', "address", False),
        ('testdata/Host/Host-2.xml', "address6", True),
    ])
    def test_has_ipv6(self, filepath, ip, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.has_ipv6(ip)
        assert expected == e.has_ip(ip)

    @pytest.mark.parametrize(("filepath", "ip", "expected"), [
        ('testdata/Host/Host-3.xml', "mac", True),
        ('testdata/Host/Host-3.xml', "mac2", False),
    ])
    def test_has_mac(self, filepath, ip, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.has_mac(ip)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', "testdata/Scripts/UnknownScript-1.xml"),
    ])
    def test_has_script_three_times(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        sxml = self.create_xml(expected)
        script = parse(sxml)

        assert 1 == len(e.get_host_scripts())
        assert e.has_hostscript(script.get_id())
        assert 3 == len(e.get_hostscript(script.get_id()))
        assert 3 == len(e.get_host_scripts()[script.get_id()])
        for hs in e.get_hostscript(script.get_id()):
            assert hs.equals(script)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', "testdata/Sequence/IPIDSequence-1.xml"),
        ('testdata/Host/Host-2.xml', "testdata/Sequence/IPIDSequence-1.xml"),
        ('testdata/Host/Host-3.xml', "testdata/Sequence/IPIDSequence-1.xml"),
        ('testdata/Host/Host-4.xml', "testdata/Sequence/IPIDSequence-1.xml"),
    ])
    def test_has_IPIDSequence(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        sxml = self.create_xml(expected)
        sequence = IPIDSequence(sxml)

        assert 1 == len(e.get_ipid_sequences())
        for s in e.get_ipid_sequences():
            assert s.equals(sequence)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', "testdata/Sequence/TCPSequence-1.xml"),
        ('testdata/Host/Host-2.xml', "testdata/Sequence/TCPSequence-1.xml"),
        ('testdata/Host/Host-3.xml', "testdata/Sequence/TCPSequence-1.xml"),
        ('testdata/Host/Host-4.xml', "testdata/Sequence/TCPSequence-1.xml"),
    ])
    def test_has_TCPSequence(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        sxml = self.create_xml(expected)
        sequence = TCPSequence(sxml)

        assert 1 == len(e.get_tcp_sequences())
        for s in e.get_tcp_sequences():
            assert s.equals(sequence)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', "testdata/Sequence/TCPTSSequence-1.xml"),
        ('testdata/Host/Host-2.xml', "testdata/Sequence/TCPTSSequence-1.xml"),
        ('testdata/Host/Host-3.xml', "testdata/Sequence/TCPTSSequence-1.xml"),
        ('testdata/Host/Host-4.xml', "testdata/Sequence/TCPTSSequence-1.xml"),
    ])
    def test_has_TCPTSSequence(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        sxml = self.create_xml(expected)
        sequence = TCPTSSequence(sxml)

        assert 1 == len(e.get_tcpts_sequences())
        for s in e.get_tcpts_sequences():
            assert s.equals(sequence)

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 1),
        ('testdata/Host/Host-2.xml', 0),
        ('testdata/Host/Host-3.xml', 0),
        ('testdata/Host/Host-4.xml', 0),
    ])
    def test_open_ports(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        ports = e.get_open_ports()
        assert expected == len(ports)
        assert ports == e.get_open_ports()
        assert None != e.get_port(22)
        assert None == e.get_port(10)
        if 0 != expected:
            assert e.has_port_open(22)
            assert not e.has_port_open(10)
            assert e.get_port(22) in e.get_ports()
            assert e.get_port_open(22) in e.get_ports()
        else:
            assert not e.has_port_open(22)
        assert len(ports) == len(e.get_open_ports_with_ids([22]))
        assert len(ports) == len(e.get_open_ports_with_script('unknownId'))

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 0),
        ('testdata/Host/Host-2.xml', 1),
        ('testdata/Host/Host-3.xml', 0),
        ('testdata/Host/Host-4.xml', 0),
    ])
    def test_closed_ports(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        ports = e.get_closed_ports()
        assert expected == len(ports)
        assert ports == e.get_closed_ports()
        assert None != e.get_port(22)
        assert None == e.get_port(10)
        if 0 != expected:
            assert e.has_port_closed(22)
            assert not e.has_port_closed(10)
            assert e.get_port(22) in e.get_ports()
            assert e.get_port_closed(22) in e.get_ports()
        else:
            assert not e.has_port_closed(22)
        assert len(ports) == len(e.get_closed_ports_with_ids([22]))
        assert len(ports) == len(e.get_closed_ports_with_script('unknownId'))

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 0),
        ('testdata/Host/Host-2.xml', 0),
        ('testdata/Host/Host-3.xml', 1),
        ('testdata/Host/Host-4.xml', 0),
    ])
    def test_filtered_ports(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        ports = e.get_filtered_ports()
        assert expected == len(ports)
        assert ports == e.get_filtered_ports()
        assert None != e.get_port(22)
        assert None == e.get_port(10)
        if 0 != expected:
            assert e.has_port_filtered(22)
            assert not e.has_port_filtered(10)
            assert e.get_port(22) in e.get_ports()
            assert e.get_port_filtered(22) in e.get_ports()
        else:
            assert not e.has_port_filtered(22)
        assert len(ports) == len(e.get_filtered_ports_with_ids([22]))
        assert len(ports) == len(e.get_filtered_ports_with_script('unknownId'))

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Host-1.xml', 0),
        ('testdata/Host/Host-2.xml', 0),
        ('testdata/Host/Host-3.xml', 0),
        ('testdata/Host/Host-4.xml', 1),
    ])
    def test_unfiltered_ports(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        ports = e.get_unfiltered_ports()
        assert expected == len(ports)
        assert ports == e.get_unfiltered_ports()
        assert None != e.get_port(22)
        assert None == e.get_port(10)
        if 0 != expected:
            assert e.has_port_unfiltered(22)
            assert not e.has_port_unfiltered(10)
            assert e.get_port(22) in e.get_ports()
            assert e.get_port_unfiltered(22) in e.get_ports()
        else:
            assert not e.has_port_unfiltered(22)
        assert len(ports) == len(e.get_unfiltered_ports_with_ids([22]))
        assert len(ports) == len(e.get_unfiltered_ports_with_script('unknownId'))

    @pytest.mark.parametrize(("filepath"), [
        ('testdata/Host/Host-1.xml'),
        ('testdata/Host/Host-2.xml'),
        ('testdata/Host/Host-3.xml'),
        ('testdata/Host/Host-4.xml'),
    ])
    def test_get_ports_with_script(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert 1 == len(e.get_ports_with_script('unknownId'))

    @pytest.mark.parametrize(("filepath"), [
        ('testdata/Host/Host-1.xml'),
        ('testdata/Host/Host-2.xml'),
        ('testdata/Host/Host-3.xml'),
        ('testdata/Host/Host-4.xml'),
    ])
    def test_get_ports_with_ids(self, filepath):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert e.has_port(22)
        assert 1 == len(e.get_ports_with_ids([22]))

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/Host-1.xml', 'testdata/Host/Host-1.xml', True),
        ('testdata/Host/Host-1.xml', 'testdata/Host/Host-2.xml', False),
        ('testdata/Host/Host-2.xml', 'testdata/Host/Host-1.xml', False),
        ('testdata/Host/Host-2.xml', 'testdata/Host/Host-2.xml', True),

    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
