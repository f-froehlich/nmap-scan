import pytest

from nmap_scan.Report.TCPReport import TCPReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestTCPReport(TestReport):

    def get_class(self):
        return TCPReport
