import pytest

from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Host.Service import Service
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.os
class TestService(BaseXMLTest):

    def create_instance(self, xml):
        return Service(xml)

    def get_all_files(self):
        return ['testdata/Host/Service-' + str(i) + '.xml' for i in range(1, 3)]

    def get_all_invalid_files(self):
        return ['testdata/Host/Service-8.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'name'),
        ('testdata/Host/Service-2.xml', 'name'),
        ('testdata/Host/Service-3.xml', 'name'),
    ])
    def test_name(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_name()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', '10'),
        ('testdata/Host/Service-2.xml', '10'),
        ('testdata/Host/Service-3.xml', '10'),
    ])
    def test_conf(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_conf()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'servicefp'),
        ('testdata/Host/Service-2.xml', 'servicefp'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_servicefp(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_service_fp()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'devicetype'),
        ('testdata/Host/Service-2.xml', 'devicetype'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_devicetype(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_device_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'ostype'),
        ('testdata/Host/Service-2.xml', 'ostype'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_ostype(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_os_type()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'hostname'),
        ('testdata/Host/Service-2.xml', 'hostname'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_hostname(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_hostname()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 20),
        ('testdata/Host/Service-2.xml', 20),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_highver(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_high_version()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 10),
        ('testdata/Host/Service-2.xml', 10),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_lowver(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_low_version()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 5),
        ('testdata/Host/Service-2.xml', 5),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_rpcnum(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_rpc_num()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'rpc'),
        ('testdata/Host/Service-2.xml', 'rpc'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_proto(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_proto()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'ssl'),
        ('testdata/Host/Service-2.xml', 'ssl'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_tunnel(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_tunnel()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'extrainfo'),
        ('testdata/Host/Service-2.xml', 'extrainfo'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_extrainfo(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_extra_info()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'product'),
        ('testdata/Host/Service-2.xml', 'product'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_product(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_product()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'version'),
        ('testdata/Host/Service-2.xml', 'version'),
        ('testdata/Host/Service-3.xml', None),
    ])
    def test_version(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_version()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', 'probed'),
        ('testdata/Host/Service-2.xml', 'probed'),
        ('testdata/Host/Service-3.xml', 'table'),
    ])
    def test_method(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_method()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Host/Service-1.xml', ['cpe1', 'cpe2']),
        ('testdata/Host/Service-2.xml', ['cpe2', 'cpe2']),
        ('testdata/Host/Service-3.xml', []),
    ])
    def test_cpes(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert len(expected) == len(e.get_cpes())

        for ex in expected:
            assert ex in e.get_cpes()

        for c in e.get_cpes():
            assert c in expected

    @pytest.mark.invalidXML
    @pytest.mark.xml
    @pytest.mark.parametrize(("filepath", "expected_error"), [
        ('testdata/Host/Service-4.xml', 'method'),
        ('testdata/Host/Service-5.xml', 'conf'),
        ('testdata/Host/Service-6.xml', 'name'),
    ])
    def test_error_on_missing_required_param(self, filepath, expected_error):
        with pytest.raises(NmapXMLParserException) as excinfo:
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Host/Service-1.xml', 'testdata/Host/Service-1.xml', True),
        ('testdata/Host/Service-1.xml', 'testdata/Host/Service-2.xml', False),
        ('testdata/Host/Service-2.xml', 'testdata/Host/Service-1.xml', False),
        ('testdata/Host/Service-2.xml', 'testdata/Host/Service-2.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)
