import pytest

from nmap_scan.Report.SCTPCookieReport import SCTPCookieReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestSCTPCookieReport(TestReport):

    def get_class(self):
        return SCTPCookieReport
