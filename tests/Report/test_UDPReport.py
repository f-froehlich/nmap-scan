import pytest

from nmap_scan.Report.UDPReport import UDPReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestUDPReport(TestReport):

    def get_class(self):
        return UDPReport
