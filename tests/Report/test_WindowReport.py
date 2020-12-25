import pytest

from nmap_scan.Report.WindowReport import WindowReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestWindowReport(TestReport):

    def get_class(self):
        return WindowReport
