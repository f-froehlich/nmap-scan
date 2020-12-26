import pytest

from nmap_scan.NmapArgs import NmapArgs


class TestNmapArgs:

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_always_dns_resolution(self):
        args = NmapArgs(always_dns_resolution='foo')
        assert 'foo' == args.get_always_dns_resolution()
        assert not args.is_locked()

        args.set_always_dns_resolution('value')
        assert 'value' == args.get_always_dns_resolution()

        args.lock()

        assert args.is_locked()
        args.set_always_dns_resolution('new_value')
        assert 'value' == args.get_always_dns_resolution()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_always_dns_resolution()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_never_dns_resolution(self):
        args = NmapArgs(never_dns_resolution='foo')
        assert 'foo' == args.get_never_dns_resolution()
        assert not args.is_locked()

        args.set_never_dns_resolution('value')
        assert 'value' == args.get_never_dns_resolution()

        args.lock()

        assert args.is_locked()
        args.set_never_dns_resolution('new_value')
        assert 'value' == args.get_never_dns_resolution()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_never_dns_resolution()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_port_ratio(self):
        args = NmapArgs(port_ratio='foo')
        assert 'foo' == args.get_port_ratio()
        assert not args.is_locked()

        args.set_port_ratio('value')
        assert 'value' == args.get_port_ratio()

        args.lock()

        assert args.is_locked()
        args.set_port_ratio('new_value')
        assert 'value' == args.get_port_ratio()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_port_ratio()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_top_ports(self):
        args = NmapArgs(top_ports='foo')
        assert 'foo' == args.get_top_ports()
        assert not args.is_locked()

        args.set_top_ports('value')
        assert 'value' == args.get_top_ports()

        args.lock()

        assert args.is_locked()
        args.set_top_ports('new_value')
        assert 'value' == args.get_top_ports()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_top_ports()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_scan_consecutively(self):
        args = NmapArgs(scan_consecutively='foo')
        assert 'foo' == args.get_scan_consecutively()
        assert not args.is_locked()

        args.set_scan_consecutively('value')
        assert 'value' == args.get_scan_consecutively()

        args.lock()

        assert args.is_locked()
        args.set_scan_consecutively('new_value')
        assert 'value' == args.get_scan_consecutively()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_scan_consecutively()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_fast_mode(self):
        args = NmapArgs(fast_mode='foo')
        assert 'foo' == args.get_fast_mode()
        assert not args.is_locked()

        args.set_fast_mode('value')
        assert 'value' == args.get_fast_mode()

        args.lock()

        assert args.is_locked()
        args.set_fast_mode('new_value')
        assert 'value' == args.get_fast_mode()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_fast_mode()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_exclude_ports(self):
        args = NmapArgs(exclude_ports='foo')
        assert 'foo' == args.get_exclude_ports()
        assert not args.is_locked()

        args.set_exclude_ports('value')
        assert 'value' == args.get_exclude_ports()

        args.lock()

        assert args.is_locked()
        args.set_exclude_ports('new_value')
        assert 'value' == args.get_exclude_ports()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_exclude_ports()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_version_all(self):
        args = NmapArgs(version_all='foo')
        assert 'foo' == args.get_version_all()
        assert not args.is_locked()

        args.set_version_all('value')
        assert 'value' == args.get_version_all()

        args.lock()

        assert args.is_locked()
        args.set_version_all('new_value')
        assert 'value' == args.get_version_all()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_version_all()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_script_trace(self):
        args = NmapArgs(script_trace='foo')
        assert 'foo' == args.get_script_trace()
        assert not args.is_locked()

        args.set_script_trace('value')
        assert 'value' == args.get_script_trace()

        args.lock()

        assert args.is_locked()
        args.set_script_trace('new_value')
        assert 'value' == args.get_script_trace()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_script_trace()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_version_light(self):
        args = NmapArgs(version_light='foo')
        assert 'foo' == args.get_version_light()
        assert not args.is_locked()

        args.set_version_light('value')
        assert 'value' == args.get_version_light()

        args.lock()

        assert args.is_locked()
        args.set_version_light('new_value')
        assert 'value' == args.get_version_light()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_version_light()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_version_intensity(self):
        args = NmapArgs(version_intensity='foo')
        assert 'foo' == args.get_version_intensity()
        assert not args.is_locked()

        args.set_version_intensity('value')
        assert 'value' == args.get_version_intensity()

        args.lock()

        assert args.is_locked()
        args.set_version_intensity('new_value')
        assert 'value' == args.get_version_intensity()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_version_intensity()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_service_discovery(self):
        args = NmapArgs(service_discovery='foo')
        assert 'foo' == args.get_service_discovery()
        assert not args.is_locked()

        args.set_service_discovery('value')
        assert 'value' == args.get_service_discovery()

        args.lock()

        assert args.is_locked()
        args.set_service_discovery('new_value')
        assert 'value' == args.get_service_discovery()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_service_discovery()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_pn(self):
        args = NmapArgs(pn='foo')
        assert 'foo' == args.get_pn()
        assert not args.is_locked()

        args.set_pn('value')
        assert 'value' == args.get_pn()

        args.lock()

        assert args.is_locked()
        args.set_pn('new_value')
        assert 'value' == args.get_pn()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_pn()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_script_args(self):
        args = NmapArgs(script_args='foo')
        assert 'foo' == args.get_script_args()
        assert not args.is_locked()

        args.set_script_args('value')
        assert 'value' == args.get_script_args()

        args.lock()

        assert args.is_locked()
        args.set_script_args('new_value')
        assert 'value' == args.get_script_args()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_script_args()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_scripts(self):
        args = NmapArgs(scripts='foo')
        assert 'foo' == args.get_scripts()
        assert not args.is_locked()

        args.set_scripts('value')
        assert 'value' == args.get_scripts()

        args.lock()

        assert args.is_locked()
        args.set_scripts('new_value')
        assert 'value' == args.get_scripts()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_scripts()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_default_script(self):
        args = NmapArgs(default_script='foo')
        assert 'foo' == args.get_default_script()
        assert not args.is_locked()

        args.set_default_script('value')
        assert 'value' == args.get_default_script()

        args.lock()

        assert args.is_locked()
        args.set_default_script('new_value')
        assert 'value' == args.get_default_script()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_default_script()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_version_trace(self):
        args = NmapArgs(version_trace='foo')
        assert 'foo' == args.get_version_trace()
        assert not args.is_locked()

        args.set_version_trace('value')
        assert 'value' == args.get_version_trace()

        args.lock()

        assert args.is_locked()
        args.set_version_trace('new_value')
        assert 'value' == args.get_version_trace()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_version_trace()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_min_hostgroup(self):
        args = NmapArgs(min_hostgroup='foo')
        assert 'foo' == args.get_min_hostgroup()
        assert not args.is_locked()

        args.set_min_hostgroup('value')
        assert 'value' == args.get_min_hostgroup()

        args.lock()

        assert args.is_locked()
        args.set_min_hostgroup('new_value')
        assert 'value' == args.get_min_hostgroup()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_min_hostgroup()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_timing(self):
        args = NmapArgs(timing='foo')
        assert 'foo' == args.get_timing()
        assert not args.is_locked()

        args.set_timing('value')
        assert 'value' == args.get_timing()

        args.lock()

        assert args.is_locked()
        args.set_timing('new_value')
        assert 'value' == args.get_timing()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_timing()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_os_scan_limit(self):
        args = NmapArgs(os_scan_limit='foo')
        assert 'foo' == args.get_os_scan_limit()
        assert not args.is_locked()

        args.set_os_scan_limit('value')
        assert 'value' == args.get_os_scan_limit()

        args.lock()

        assert args.is_locked()
        args.set_os_scan_limit('new_value')
        assert 'value' == args.get_os_scan_limit()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_os_scan_limit()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_os_guess(self):
        args = NmapArgs(os_guess='foo')
        assert 'foo' == args.get_os_guess()
        assert not args.is_locked()

        args.set_os_guess('value')
        assert 'value' == args.get_os_guess()

        args.lock()

        assert args.is_locked()
        args.set_os_guess('new_value')
        assert 'value' == args.get_os_guess()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_os_guess()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_os_detection(self):
        args = NmapArgs(os_detection='foo')
        assert 'foo' == args.get_os_detection()
        assert not args.is_locked()

        args.set_os_detection('value')
        assert 'value' == args.get_os_detection()

        args.lock()

        assert args.is_locked()
        args.set_os_detection('new_value')
        assert 'value' == args.get_os_detection()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_os_detection()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_min_rtt_timeout(self):
        args = NmapArgs(min_rtt_timeout='foo')
        assert 'foo' == args.get_min_rtt_timeout()
        assert not args.is_locked()

        args.set_min_rtt_timeout('value')
        assert 'value' == args.get_min_rtt_timeout()

        args.lock()

        assert args.is_locked()
        args.set_min_rtt_timeout('new_value')
        assert 'value' == args.get_min_rtt_timeout()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_min_rtt_timeout()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_parallelism(self):
        args = NmapArgs(max_parallelism='foo')
        assert 'foo' == args.get_max_parallelism()
        assert not args.is_locked()

        args.set_max_parallelism('value')
        assert 'value' == args.get_max_parallelism()

        args.lock()

        assert args.is_locked()
        args.set_max_parallelism('new_value')
        assert 'value' == args.get_max_parallelism()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_parallelism()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_min_parallelism(self):
        args = NmapArgs(min_parallelism='foo')
        assert 'foo' == args.get_min_parallelism()
        assert not args.is_locked()

        args.set_min_parallelism('value')
        assert 'value' == args.get_min_parallelism()

        args.lock()

        assert args.is_locked()
        args.set_min_parallelism('new_value')
        assert 'value' == args.get_min_parallelism()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_min_parallelism()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_hostgroup(self):
        args = NmapArgs(max_hostgroup='foo')
        assert 'foo' == args.get_max_hostgroup()
        assert not args.is_locked()

        args.set_max_hostgroup('value')
        assert 'value' == args.get_max_hostgroup()

        args.lock()

        assert args.is_locked()
        args.set_max_hostgroup('new_value')
        assert 'value' == args.get_max_hostgroup()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_hostgroup()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_scan_delay(self):
        args = NmapArgs(scan_delay='foo')
        assert 'foo' == args.get_scan_delay()
        assert not args.is_locked()

        args.set_scan_delay('value')
        assert 'value' == args.get_scan_delay()

        args.lock()

        assert args.is_locked()
        args.set_scan_delay('new_value')
        assert 'value' == args.get_scan_delay()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_scan_delay()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_host_timeout(self):
        args = NmapArgs(host_timeout='foo')
        assert 'foo' == args.get_host_timeout()
        assert not args.is_locked()

        args.set_host_timeout('value')
        assert 'value' == args.get_host_timeout()

        args.lock()

        assert args.is_locked()
        args.set_host_timeout('new_value')
        assert 'value' == args.get_host_timeout()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_host_timeout()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_retries(self):
        args = NmapArgs(max_retries='foo')
        assert 'foo' == args.get_max_retries()
        assert not args.is_locked()

        args.set_max_retries('value')
        assert 'value' == args.get_max_retries()

        args.lock()

        assert args.is_locked()
        args.set_max_retries('new_value')
        assert 'value' == args.get_max_retries()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_retries()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_initial_rtt_timeout(self):
        args = NmapArgs(initial_rtt_timeout='foo')
        assert 'foo' == args.get_initial_rtt_timeout()
        assert not args.is_locked()

        args.set_initial_rtt_timeout('value')
        assert 'value' == args.get_initial_rtt_timeout()

        args.lock()

        assert args.is_locked()
        args.set_initial_rtt_timeout('new_value')
        assert 'value' == args.get_initial_rtt_timeout()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_initial_rtt_timeout()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_privileged(self):
        args = NmapArgs(privileged='foo')
        assert 'foo' == args.get_privileged()
        assert not args.is_locked()

        args.set_privileged('value')
        assert 'value' == args.get_privileged()

        args.lock()

        assert args.is_locked()
        args.set_privileged('new_value')
        assert 'value' == args.get_privileged()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_privileged()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_rtt_timeout(self):
        args = NmapArgs(max_rtt_timeout='foo')
        assert 'foo' == args.get_max_rtt_timeout()
        assert not args.is_locked()

        args.set_max_rtt_timeout('value')
        assert 'value' == args.get_max_rtt_timeout()

        args.lock()

        assert args.is_locked()
        args.set_max_rtt_timeout('new_value')
        assert 'value' == args.get_max_rtt_timeout()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_rtt_timeout()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_decoys(self):
        args = NmapArgs(decoys='foo')
        assert 'foo' == args.get_decoys()
        assert not args.is_locked()

        args.set_decoys('value')
        assert 'value' == args.get_decoys()

        args.lock()

        assert args.is_locked()
        args.set_decoys('new_value')
        assert 'value' == args.get_decoys()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_decoys()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_mtu(self):
        args = NmapArgs(mtu='foo')
        assert 'foo' == args.get_mtu()
        assert not args.is_locked()

        args.set_mtu('value')
        assert 'value' == args.get_mtu()

        args.lock()

        assert args.is_locked()
        args.set_mtu('new_value')
        assert 'value' == args.get_mtu()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_mtu()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_misc_a(self):
        args = NmapArgs(misc_a='foo')
        assert 'foo' == args.get_misc_a()
        assert not args.is_locked()

        args.set_misc_a('value')
        assert 'value' == args.get_misc_a()

        args.lock()

        assert args.is_locked()
        args.set_misc_a('new_value')
        assert 'value' == args.get_misc_a()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_misc_a()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_datadir(self):
        args = NmapArgs(datadir='foo')
        assert 'foo' == args.get_datadir()
        assert not args.is_locked()

        args.set_datadir('value')
        assert 'value' == args.get_datadir()

        args.lock()

        assert args.is_locked()
        args.set_datadir('new_value')
        assert 'value' == args.get_datadir()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_datadir()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_ipv6_scan(self):
        args = NmapArgs(ipv6_scan='foo')
        assert 'foo' == args.get_ipv6_scan()
        assert not args.is_locked()

        args.set_ipv6_scan('value')
        assert 'value' == args.get_ipv6_scan()

        args.lock()

        assert args.is_locked()
        args.set_ipv6_scan('new_value')
        assert 'value' == args.get_ipv6_scan()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_ipv6_scan()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_rate(self):
        args = NmapArgs(max_rate='foo')
        assert 'foo' == args.get_max_rate()
        assert not args.is_locked()

        args.set_max_rate('value')
        assert 'value' == args.get_max_rate()

        args.lock()

        assert args.is_locked()
        args.set_max_rate('new_value')
        assert 'value' == args.get_max_rate()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_rate()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_min_rate(self):
        args = NmapArgs(min_rate='foo')
        assert 'foo' == args.get_min_rate()
        assert not args.is_locked()

        args.set_min_rate('value')
        assert 'value' == args.get_min_rate()

        args.lock()

        assert args.is_locked()
        args.set_min_rate('new_value')
        assert 'value' == args.get_min_rate()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_min_rate()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_data_string(self):
        args = NmapArgs(data_string='foo')
        assert 'foo' == args.get_data_string()
        assert not args.is_locked()

        args.set_data_string('value')
        assert 'value' == args.get_data_string()

        args.lock()

        assert args.is_locked()
        args.set_data_string('new_value')
        assert 'value' == args.get_data_string()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_data_string()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_data(self):
        args = NmapArgs(data='foo')
        assert 'foo' == args.get_data()
        assert not args.is_locked()

        args.set_data('value')
        assert 'value' == args.get_data()

        args.lock()

        assert args.is_locked()
        args.set_data('new_value')
        assert 'value' == args.get_data()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_data()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_proxies(self):
        args = NmapArgs(proxies='foo')
        assert 'foo' == args.get_proxies()
        assert not args.is_locked()

        args.set_proxies('value')
        assert 'value' == args.get_proxies()

        args.lock()

        assert args.is_locked()
        args.set_proxies('new_value')
        assert 'value' == args.get_proxies()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_proxies()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_source_port(self):
        args = NmapArgs(source_port='foo')
        assert 'foo' == args.get_source_port()
        assert not args.is_locked()

        args.set_source_port('value')
        assert 'value' == args.get_source_port()

        args.lock()

        assert args.is_locked()
        args.set_source_port('new_value')
        assert 'value' == args.get_source_port()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_source_port()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_send_ip(self):
        args = NmapArgs(send_ip='foo')
        assert 'foo' == args.get_send_ip()
        assert not args.is_locked()

        args.set_send_ip('value')
        assert 'value' == args.get_send_ip()

        args.lock()

        assert args.is_locked()
        args.set_send_ip('new_value')
        assert 'value' == args.get_send_ip()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_send_ip()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_unprivileged(self):
        args = NmapArgs(unprivileged='foo')
        assert 'foo' == args.get_unprivileged()
        assert not args.is_locked()

        args.set_unprivileged('value')
        assert 'value' == args.get_unprivileged()

        args.lock()

        assert args.is_locked()
        args.set_unprivileged('new_value')
        assert 'value' == args.get_unprivileged()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_unprivileged()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_send_eth(self):
        args = NmapArgs(send_eth='foo')
        assert 'foo' == args.get_send_eth()
        assert not args.is_locked()

        args.set_send_eth('value')
        assert 'value' == args.get_send_eth()

        args.lock()

        assert args.is_locked()
        args.set_send_eth('new_value')
        assert 'value' == args.get_send_eth()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_send_eth()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_max_scan_delay(self):
        args = NmapArgs(max_scan_delay='foo')
        assert 'foo' == args.get_max_scan_delay()
        assert not args.is_locked()

        args.set_max_scan_delay('value')
        assert 'value' == args.get_max_scan_delay()

        args.lock()

        assert args.is_locked()
        args.set_max_scan_delay('new_value')
        assert 'value' == args.get_max_scan_delay()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_max_scan_delay()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_interface(self):
        args = NmapArgs(interface='foo')
        assert 'foo' == args.get_interface()
        assert not args.is_locked()

        args.set_interface('value')
        assert 'value' == args.get_interface()

        args.lock()

        assert args.is_locked()
        args.set_interface('new_value')
        assert 'value' == args.get_interface()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_interface()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_spoof_ip(self):
        args = NmapArgs(spoof_ip='foo')
        assert 'foo' == args.get_spoof_ip()
        assert not args.is_locked()

        args.set_spoof_ip('value')
        assert 'value' == args.get_spoof_ip()

        args.lock()

        assert args.is_locked()
        args.set_spoof_ip('new_value')
        assert 'value' == args.get_spoof_ip()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_spoof_ip()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_bad_sum(self):
        args = NmapArgs(bad_sum='foo')
        assert 'foo' == args.get_bad_sum()
        assert not args.is_locked()

        args.set_bad_sum('value')
        assert 'value' == args.get_bad_sum()

        args.lock()

        assert args.is_locked()
        args.set_bad_sum('new_value')
        assert 'value' == args.get_bad_sum()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_bad_sum()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_spoof_mac(self):
        args = NmapArgs(spoof_mac='foo')
        assert 'foo' == args.get_spoof_mac()
        assert not args.is_locked()

        args.set_spoof_mac('value')
        assert 'value' == args.get_spoof_mac()

        args.lock()

        assert args.is_locked()
        args.set_spoof_mac('new_value')
        assert 'value' == args.get_spoof_mac()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_spoof_mac()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_ttl(self):
        args = NmapArgs(ttl='foo')
        assert 'foo' == args.get_ttl()
        assert not args.is_locked()

        args.set_ttl('value')
        assert 'value' == args.get_ttl()

        args.lock()

        assert args.is_locked()
        args.set_ttl('new_value')
        assert 'value' == args.get_ttl()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_ttl()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_ip_options(self):
        args = NmapArgs(ip_options='foo')
        assert 'foo' == args.get_ip_options()
        assert not args.is_locked()

        args.set_ip_options('value')
        assert 'value' == args.get_ip_options()

        args.lock()

        assert args.is_locked()
        args.set_ip_options('new_value')
        assert 'value' == args.get_ip_options()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_ip_options()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_data_length(self):
        args = NmapArgs(data_length='foo')
        assert 'foo' == args.get_data_length()
        assert not args.is_locked()

        args.set_data_length('value')
        assert 'value' == args.get_data_length()

        args.lock()

        assert args.is_locked()
        args.set_data_length('new_value')
        assert 'value' == args.get_data_length()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_data_length()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_ports(self):
        args = NmapArgs(ports='foo')
        assert 'foo' == args.get_ports()
        assert not args.is_locked()

        args.set_ports('value')
        assert 'value' == args.get_ports()

        args.lock()

        assert args.is_locked()
        args.set_ports('new_value')
        assert 'value' == args.get_ports()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_ports()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_traceroute(self):
        args = NmapArgs(traceroute='foo')
        assert 'foo' == args.get_traceroute()
        assert not args.is_locked()

        args.set_traceroute('value')
        assert 'value' == args.get_traceroute()

        args.lock()

        assert args.is_locked()
        args.set_traceroute('new_value')
        assert 'value' == args.get_traceroute()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_traceroute()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_system_dns(self):
        args = NmapArgs(system_dns='foo')
        assert 'foo' == args.get_system_dns()
        assert not args.is_locked()

        args.set_system_dns('value')
        assert 'value' == args.get_system_dns()

        args.lock()

        assert args.is_locked()
        args.set_system_dns('new_value')
        assert 'value' == args.get_system_dns()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_system_dns()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_dns_servers(self):
        args = NmapArgs(dns_servers='foo')
        assert 'foo' == args.get_dns_servers()
        assert not args.is_locked()

        args.set_dns_servers('value')
        assert 'value' == args.get_dns_servers()

        args.lock()

        assert args.is_locked()
        args.set_dns_servers('new_value')
        assert 'value' == args.get_dns_servers()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_dns_servers()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_exclude_hosts(self):
        args = NmapArgs(exclude_hosts='foo')
        assert 'foo' == args.get_exclude_hosts()
        assert not args.is_locked()

        args.set_exclude_hosts('value')
        assert 'value' == args.get_exclude_hosts()

        args.lock()

        assert args.is_locked()
        args.set_exclude_hosts('new_value')
        assert 'value' == args.get_exclude_hosts()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_exclude_hosts()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_num_hosts(self):
        args = NmapArgs(num_hosts='foo')
        assert 'foo' == args.get_num_hosts()
        assert not args.is_locked()

        args.set_num_hosts('value')
        assert 'value' == args.get_num_hosts()

        args.lock()

        assert args.is_locked()
        args.set_num_hosts('new_value')
        assert 'value' == args.get_num_hosts()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_num_hosts()

    @pytest.mark.nmap
    @pytest.mark.nmapargs
    def test_set_hosts(self):
        args = NmapArgs(hosts='foo')
        assert 'foo' == args.get_hosts()
        assert not args.is_locked()

        args.set_hosts('value')
        assert 'value' == args.get_hosts()

        args.lock()

        assert args.is_locked()
        args.set_hosts('new_value')
        assert 'value' == args.get_hosts()

        cloned_args = args.clone()
        assert not cloned_args.is_locked()
        assert 'value' == cloned_args.get_hosts()
