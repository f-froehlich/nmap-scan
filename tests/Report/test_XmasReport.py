import pytest

from nmap_scan.Report.XmasReport import XmasReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestXmasReport(TestReport):

    def get_class(self):
        return XmasReport
