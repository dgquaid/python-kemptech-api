from nose.tools import assert_equal, assert_raises, assert_true

# handle py3 and py2 cases:
try:
    import unittest.mock as mock
except ImportError:
    import mock

patch = mock.patch

import python_kemptech_api.exceptions as exceptions
from python_kemptech_api.objects import VirtualService, RealServer


class Test_RealServer:

    def setup(self):
        lm_info = {
            "endpoint": "https://bal:2fourall@1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            }
        self.vs = VirtualService(lm_info, "1.1.1.2")
        self.vs_info = {
            'vs': self.vs,
            "endpoint": "https://bal:2fourall@1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            }
        self.rs = RealServer(self.vs_info, "1.1.1.2")

    def test_init_with_no_endpoint(self):
        vs_info_with_no_endpoint = {'vs': self.vs, "ip_address": "1.1.1.1"}
        with assert_raises(exceptions.RealServerMissingLoadmasterInfo):
            RealServer(vs_info_with_no_endpoint, "1.1.1.2")

    def test_init_with_no_ipaddress(self):
        vs_info_with_no_ip_address = {
            'vs': self.vs,
            "endpoint": "https://bal:2fourall@1.1.1.1:443/access"
            }
        with assert_raises(exceptions.RealServerMissingLoadmasterInfo):
            RealServer(vs_info_with_no_ip_address, "1.1.1.2")

    def test_init_with_vs(self):
        vs_info_with_no_vs = {
             "ip_address": "1.1.1.1",
            "endpoint": "https://bal:2fourall@1.1.1.1:443/access"
            }
        with assert_raises(exceptions.RealServerMissingVirtualServiceInfo):
            RealServer(vs_info_with_no_vs, "1.1.1.2")

    def test_str(self):
        expected = 'Real Server 1.1.1.2 on Virtual Service TCP 1.1.1.2:80 on LoadMaster 1.1.1.1'
        assert_equal(str(self.rs),  expected)

    def test_get_base_parameters(self):
        base_params = self.rs._get_base_parameters()
        assert_true(isinstance(base_params['vs'], VirtualService))
        del base_params['vs']
        expected_params = {
            'prot': None,
            'rsport': 80,
            'rs': '1.1.1.2',
            'port': None
            }
        assert_equal(base_params, expected_params)

    def test_to_api_dict(self):
        actual = self.rs.to_api_dict()
        assert_true (isinstance(actual['vs'], VirtualService))
        del actual['vs']
        expected = {'rs': '1.1.1.2', 'rsport': 80}
        assert_equal(actual, expected)
