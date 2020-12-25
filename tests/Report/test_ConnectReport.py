import pytest

from nmap_scan.Report.ConnectReport import ConnectReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestConnectReport(TestReport):

    def get_class(self):
        return ConnectReport
