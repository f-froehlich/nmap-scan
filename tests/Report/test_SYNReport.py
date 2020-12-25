import pytest

from nmap_scan.Report.SynReport import SynReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestSynReport(TestReport):

    def get_class(self):
        return SynReport
