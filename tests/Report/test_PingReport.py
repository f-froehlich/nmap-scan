import pytest

from nmap_scan.Report.PingReport import PingReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestPingReport(TestReport):

    def get_class(self):
        return PingReport
