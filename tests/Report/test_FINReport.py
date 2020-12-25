import pytest

from nmap_scan.Report.FINReport import FINReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestFINReport(TestReport):

    def get_class(self):
        return FINReport
