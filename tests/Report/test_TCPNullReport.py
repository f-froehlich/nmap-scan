import pytest

from nmap_scan.Report.TCPNullReport import TCPNullReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestTCPNullReport(TestReport):

    def get_class(self):
        return TCPNullReport
