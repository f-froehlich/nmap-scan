import pytest

from nmap_scan.Report.IPReport import IPReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestIPReport(TestReport):

    def get_class(self):
        return IPReport
