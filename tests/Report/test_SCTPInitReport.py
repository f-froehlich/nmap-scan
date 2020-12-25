import pytest

from nmap_scan.Report.SCTPInitReport import SCTPInitReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestSCTPInitReport(TestReport):

    def get_class(self):
        return SCTPInitReport
