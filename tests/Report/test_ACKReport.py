import pytest

from nmap_scan.Report.ACKReport import ACKReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestACKReport(TestReport):

    def get_class(self):
        return ACKReport
