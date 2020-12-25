import pytest

from nmap_scan.Report.MaimonReport import MaimonReport
from tests.Report.test_Report import TestReport


@pytest.mark.report
class TestMaimonReport(TestReport):

    def get_class(self):
        return MaimonReport
