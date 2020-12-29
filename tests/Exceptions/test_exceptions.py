import pytest

from nmap_scan.Exceptions.CallbackException import CallbackException
from nmap_scan.Exceptions.LogicException import LogicException
from nmap_scan.Exceptions.NmapConfigurationException import NmapConfigurationException
from nmap_scan.Exceptions.NmapExecutionException import NmapExecutionException
from nmap_scan.Exceptions.NmapNotInstalledException import NmapNotInstalledException
from nmap_scan.Exceptions.NmapPasswordRequiredException import NmapPasswordRequiredException
from nmap_scan.Exceptions.NmapScanMethodUnknownException import NmapScanMethodUnknownException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException
from nmap_scan.Exceptions.ReportCombineException import ReportCombineException


@pytest.mark.parametrize(("exception"), [
    LogicException,
    NmapExecutionException,
    NmapNotInstalledException,
    NmapPasswordRequiredException,
    NmapScanMethodUnknownException,
    NmapXMLParserException,
    NmapConfigurationException,
    CallbackException,
    ReportCombineException,
])
def test_error_on_missing_required_param(exception):
    with pytest.raises(exception) as excinfo:
        raise exception()
