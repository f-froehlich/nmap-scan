import pytest

from nmap_scan.Exceptions.NmapScanMethodUnknownException import NmapScanMethodUnknownException
from nmap_scan.NmapScanMethods import NmapScanMethods


class TestNmapMethods:

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_error_on_unknown_scan_method(self):
        with pytest.raises(NmapScanMethodUnknownException) as excinfo:
            methods = NmapScanMethods()
            methods.get_name_of_method('foo')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_TCP(self):
        assert '' == NmapScanMethods.TCP

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_TCP(self):
        methods = NmapScanMethods()
        assert 'TCP' == methods.get_name_of_method('')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_TCP(self):
        methods = NmapScanMethods()
        assert not methods.require_root('')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_TCP_NULL(self):
        assert '-sN' == NmapScanMethods.TCP_NULL

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_TCP_NULL(self):
        methods = NmapScanMethods()
        assert 'TCP_NULL' == methods.get_name_of_method('-sN')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_TCP_NULL(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sN')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_SYN(self):
        assert '-sS' == NmapScanMethods.SYN

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_SYN(self):
        methods = NmapScanMethods()
        assert 'SYN' == methods.get_name_of_method('-sS')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_SYN(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sS')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_UDP(self):
        assert '-sU' == NmapScanMethods.UDP

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_UDP(self):
        methods = NmapScanMethods()
        assert 'UDP' == methods.get_name_of_method('-sU')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_UDP(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sU')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_LIST(self):
        assert '-sL' == NmapScanMethods.LIST

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_LIST(self):
        methods = NmapScanMethods()
        assert 'LIST' == methods.get_name_of_method('-sL')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_LIST(self):
        methods = NmapScanMethods()
        assert not methods.require_root('-sL')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_PING(self):
        assert '-sn' == NmapScanMethods.PING

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_PING(self):
        methods = NmapScanMethods()
        assert 'PING' == methods.get_name_of_method('-sn')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_PING(self):
        methods = NmapScanMethods()
        assert not methods.require_root('-sn')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_CONNECT(self):
        assert '-sT' == NmapScanMethods.CONNECT

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_CONNECT(self):
        methods = NmapScanMethods()
        assert 'CONNECT' == methods.get_name_of_method('-sT')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_CONNECT(self):
        methods = NmapScanMethods()
        assert not methods.require_root('-sT')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_ACK(self):
        assert '-sA' == NmapScanMethods.ACK

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_ACK(self):
        methods = NmapScanMethods()
        assert 'ACK' == methods.get_name_of_method('-sA')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_ACK(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sA')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_WINDOW(self):
        assert '-sW' == NmapScanMethods.WINDOW

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_WINDOW(self):
        methods = NmapScanMethods()
        assert 'WINDOW' == methods.get_name_of_method('-sW')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_WINDOW(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sW')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_MAIMON(self):
        assert '-sM' == NmapScanMethods.MAIMON

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_MAIMON(self):
        methods = NmapScanMethods()
        assert 'MAIMON' == methods.get_name_of_method('-sM')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_MAIMON(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sM')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_FIN(self):
        assert '-sF' == NmapScanMethods.FIN

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_FIN(self):
        methods = NmapScanMethods()
        assert 'FIN' == methods.get_name_of_method('-sF')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_FIN(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sF')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_XMAS(self):
        assert '-sX' == NmapScanMethods.XMAS

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_XMAS(self):
        methods = NmapScanMethods()
        assert 'XMAS' == methods.get_name_of_method('-sX')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_XMAS(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sX')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_IP(self):
        assert '-sO' == NmapScanMethods.IP

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_IP(self):
        methods = NmapScanMethods()
        assert 'IP' == methods.get_name_of_method('-sO')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_IP(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sO')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_SCTP_INIT(self):
        assert '-sY' == NmapScanMethods.SCTP_INIT

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_SCTP_INIT(self):
        methods = NmapScanMethods()
        assert 'SCTP_INIT' == methods.get_name_of_method('-sY')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_SCTP_INIT(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sY')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_value_SCTP_COOKIE(self):
        assert '-sZ' == NmapScanMethods.SCTP_COOKIE

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_name_SCTP_COOKIE(self):
        methods = NmapScanMethods()
        assert 'SCTP_COOKIE' == methods.get_name_of_method('-sZ')

    @pytest.mark.nmap
    @pytest.mark.nmapmethods
    def test_privileges_SCTP_COOKIE(self):
        methods = NmapScanMethods()
        assert methods.require_root('-sZ')
