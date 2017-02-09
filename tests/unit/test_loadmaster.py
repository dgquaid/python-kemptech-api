from nose.tools import (
    assert_equal, assert_raises, assert_true,
    assert_is_none, assert_not_in, assert_greater, assert_less,
    assert_greater_equal, assert_less_equal, assert_not_equal, assert_false)

import requests
from requests import Session

# handle py3 and py2 cases:
try:
    import unittest.mock as mock
except ImportError:
    import mock

patch = mock.patch
sentinel = mock.sentinel

from python_kemptech_api import models
from python_kemptech_api import utils
from python_kemptech_api.objects import VirtualService, Interface
from python_kemptech_api.models import LoadMaster, BaseKempAppliance
import python_kemptech_api.exceptions as exceptions


def test_endpoint():
    lm = LoadMaster('ip', 'user', 'pw', 'port')
    expected = "https://user:pw@ip:port/access"
    assert_equal(expected, lm.endpoint)


def test_send_response_ok():
    with patch.object(utils, 'is_successful') as is_successful:
        is_successful.return_value = True
        with patch.object(utils, 'parse_to_dict') as parse_to_dict:
            utils.send_response('any_response')
            assert_true(parse_to_dict.called)


def test_send_response_fail():
    with patch.object(utils, 'is_successful') as is_successful:
        is_successful.return_value = False
        with patch.object(utils, 'get_error_msg') as get_error_msg:
            get_error_msg.return_value = None
            with assert_raises(exceptions.KempTechApiException):
                utils.send_response('any_response')


def test_repr():
    lm = LoadMaster('192.168.0.1', 'user', 'pw', 432)
    assert_equal(str(lm), '192.168.0.1:432')


class Test_get_parameter:

    def setup(self):
        self.p_get = patch.object(LoadMaster, '_get')
        self.p_get.start()
        self.p_get_data_field = patch.object(models, 'get_data_field')
        self.get_data_field = self.p_get_data_field.start()

        self.lm = LoadMaster('ip', 'user', 'pw')

    def teardown(self):
        self.p_get.stop()
        self.p_get_data_field.stop()

    def test_dict(self):
        self.get_data_field.return_value = {'a': 'dict', 'b': 'day'}
        res = self.lm.get_parameter('a-param')
        assert_equal("a='dict'b='day'", res)


    def test_str(self):
        self.get_data_field.return_value = 'a string'
        res = self.lm.get_parameter('a-param')
        assert_equal('a string', res)


class Test_set_parameter:

    def setup(self):
        self.p_get = patch.object(LoadMaster, '_get')
        self.p_get.start()
        self.p_is_successful = patch.object(models, 'is_successful')
        self.is_successful = self.p_is_successful.start()

        self.lm = LoadMaster('ip', 'user', 'pw')

    def teardown(self):
        self.p_get.stop()
        self.p_is_successful.stop()

    def test_ok(self):
        self.is_successful.return_value = True
        res = self.lm.set_parameter('a', 'b')
        assert_is_none(res)

    def test_fail(self):
        self.is_successful.return_value = False
        with assert_raises(exceptions.LoadMasterParameterError):
            self.lm.set_parameter('a', 'b')


class Test_virtual_service_crud:

    def setup(self):
        self.lm = LoadMaster("1.1.1.1", "bal", "2fourall")

    def test_create_virtual_service_factory(self):
        vs = self.lm.create_virtual_service("1.1.1.2", 90, "tcp")
        assert_equal(isinstance(vs, VirtualService), True)

    def test_no_data_exists(self):
        with patch.object(LoadMaster, 'build_virtual_service') as build_virtual_service:
            with patch.object(models, 'get_data') as get_data:
                with patch.object(LoadMaster, '_get'):
                    build_virtual_service.side_effect = sorted
                    get_data. return_value = {}
                    res = self.lm.get_virtual_services()
        expected = []
        assert_equal(res, expected)


class Test_get_virtual_service:

    def setup(self):
        self.lm = LoadMaster("1.1.1.1", "bal", "2fourall")

    def test_with_index(self):
        with patch.object(LoadMaster, 'build_virtual_service') as build_virtual_service:
            with patch.object(models, 'get_data'):
                with patch.object(LoadMaster, '_get'):
                    build_virtual_service.return_value = sentinel.vs
                    res = self.lm.get_virtual_service(index=12)
        assert_equal(res, sentinel.vs)

    def test_without_index(self):
        with patch.object(LoadMaster, 'build_virtual_service') as build_virtual_service:
            with patch.object(models, 'get_data'):
                with patch.object(LoadMaster, '_get'):
                    build_virtual_service.return_value = sentinel.vs
                    res =  self.lm.get_virtual_service(
                        address='1.1.1.1',
                        port=80,
                        protocol='tcp'
                    )
        assert_equal(res, sentinel.vs)


class TestLmApiWrapperCalls:

    def setup(self):
        self.p__get = patch.object(LoadMaster, '_get')
        self._get = self.p__get.start()
        self.p__post = patch.object(LoadMaster, '_post')
        self._post = self.p__post.start()
        self.p_send_response = patch.object(models, 'send_response')
        self.send_response = self.p_send_response.start()
        self.p_is_successful = patch.object(models, 'is_successful')
        self.is_successful = self.p_is_successful.start()
        self.p_get = patch.object(Session, 'get')
        self.get = self.p_get.start()

        self.lm = LoadMaster("1.1.1.1", "bal", "1fourall")

    def teardown(self):
        self.p__get.stop()
        self.p__post.stop()
        self.p_send_response.stop()
        self.p_is_successful.stop()
        self.p_get.stop()

    def test_stats(self):
        self.lm.stats()
        self.lm._get.assert_called_with('/stats')

    def test_update_firmware(self):
        file = "file"
        self.lm.version = "V7.1.40"
        self.lm.update_firmware(file)
        self.lm._post.assert_called_with('/installpatch', file)
        assert_is_none(self.lm.version)

    def test_restore_firmware(self):
        self.lm.version = "V7.1.40"
        self.lm.restore_firmware()
        self.lm._get.assert_called_with('/restorepatch')
        assert_is_none(self.lm.version)

    def test_shutdown(self):
        self.lm.shutdown()
        self.lm._get.assert_called_with('/shutdown')

    def test_reboot(self):
        self.lm.reboot()
        self.lm._get.assert_called_with('/reboot')

    def test_get_sdn_controller(self):
        self.lm.get_sdn_controller()
        self.lm._get.assert_called_with('/getsdncontroller')

    def test_get_license_info(self):
        self.lm.get_license_info()
        self.lm._get.assert_called_with('360/licenseinfo')
        self.lm._get.side_effect = exceptions.KempTechApiException
        with assert_raises(exceptions.KempTechApiException):
            self.lm.get_license_info()

    def test_list_addons(self):
        self.lm.list_addons()
        self.lm._get.assert_called_with('/listaddon')

    def test_upload_template(self):
        file = 'file'
        self.lm.upload_template(file)
        self.lm._post.assert_called_with('/uploadtemplate', file)

    def test_delete_template(self):
        name = 'template_name'
        self.lm.delete_template(name)
        params = {'name': name}
        self.lm._get.assert_called_with('/deltemplate', parameters=params)

    def test_get_sdn_info(self):
        self.lm.get_sdn_info()
        self.lm._get.assert_called_with('/sdninfo')

    def test_restore_backup(self):
        file = 'file'
        backup_type = 2
        self.lm.restore_backup(backup_type, file)
        params = {'type': backup_type}
        self.lm._post.assert_called_with('/restore', file=file, parameters=params)

    def test_alsi_license(self):
        kempid = 's@s.com'
        password = 'p4ss'
        self.lm.alsi_license(kempid, password)
        params = {
            'kempid': kempid,
            'password': password,
        }
        self.lm._get.assert_called_with('/alsilicense', parameters=params)

    def test_set_initial_password(self):
        password = 'p4ss'
        self.lm.set_initial_password(password)
        params = {
            'passwd': password,
        }
        self.lm._get.assert_called_with('/set_initial_passwd', parameters=params)

    def test_kill_asl_instance(self):
        self.lm.kill_asl_instance()
        self.lm._get.assert_called_with('/killaslinstance')

    def test_add_local_user(self):
        user = 'shane'
        password = 'p4ss'
        radius = False
        self.lm.add_local_user(user, password, radius)
        params = {
            'user': user,
            'radius': 'n',
            'password': password,
        }
        self.lm._get.assert_called_with('/useraddlocal', params)

    def test_delete_local_user(self):
        user = 'shane'
        self.lm.delete_local_user(user)
        params = {'user': user}
        self.lm._get.assert_called_with('/userdellocal', params)

    def test_set_user_perms_as_list(self):
        user = 'shane'
        perms = ['root', 'vs']
        self.lm.set_user_perms(user, perms)
        params = {
            'user': user,
            'perms': 'root,vs',
        }
        self.lm._get.assert_called_with('/usersetperms', params)

    def test_set_user_perms_as_string(self):
        user = 'shane'
        perms = 'root'
        self.lm.set_user_perms(user, perms)
        params = {
            'user': user,
            'perms': 'root',
        }
        self.lm._get.assert_called_with('/usersetperms', params)

    def test_new_user_cert(self):
        user = 'shane'
        perms = ['root', 'vs']
        self.lm.new_user_cert(user)
        params = {'user': user}
        self.lm._get.assert_called_with('/usernewcert', params)

    def test_operator_overloads(self):
        lm1 = LoadMaster("1.1.1.1", cert="sdf")
        lm2 = LoadMaster("1.1.1.2", cert="sdff")
        lm1.version = "7.1.34.3"
        lm2.version = "7.1.34.3"
        assert_equal(lm1, lm2)
        assert_less_equal(lm1, lm2)
        assert_greater_equal(lm1, lm2)
        lm2.version = "7.1.35"
        assert_greater(lm2, lm1)
        assert_greater_equal(lm2, lm1)
        assert_less(lm1, lm2)
        assert_less_equal(lm1, lm2)
        assert_not_equal(lm1, lm2)

    def test_operator_overloads_fail_case(self):
        lm1 = LoadMaster("1.1.1.1", cert="sdf")
        lm2 = object()
        lm1.version = "7.1.34.3"
        assert_false(lm1 == lm2)
        assert_true(lm1 != lm2)
        assert_false(lm1 < lm2)
        assert_false(lm1 > lm2)
        assert_false(lm1 <= lm2)
        assert_false(lm1 >= lm2)

    def test_new_enable_api_url(self):
        resp = mock.Mock()
        resp.status_code = 200
        self.get.return_value = resp
        assert_true(self.lm.enable_api())

    def test_new_enable_api_url_wrong_credentials(self):
        resp = mock.Mock()
        resp.status_code = 401
        self.get.return_value = resp
        with assert_raises(exceptions.KempTechApiException):
            self.lm.enable_api()

    def test_old_enable_api_url(self):
        with patch.object(BaseKempAppliance, "_do_request_no_api") as do_request:
            do_request.side_effect = [404, 200, 200, 200]
            self.lm.enable_api(True)

    def test_old_enable_api_url_wrong_credentials(self):
        with patch.object(BaseKempAppliance, "_do_request_no_api") as do_request:
            with assert_raises(exceptions.KempTechApiException):
                do_request.side_effect = [404, 200, 200, 404]
                self.lm.enable_api(True)

    def test_old_enable_api_url_logout_fails(self):
        with patch.object(BaseKempAppliance, "_do_request_no_api") as do_request:
            with assert_raises(exceptions.KempTechApiException):
                do_request.side_effect = [404, 200, 400]
                self.lm.enable_api(True)

    def test_enable_api_exception(self):
        with patch.object(LoadMaster, "get_parameter") as get_parameter:
            get_parameter.return_value = "7.1.30"
            self.get.side_effect = requests.exceptions.HTTPError
            with assert_raises(exceptions.KempTechApiException) as e:
                self.lm.enable_api()

    def test_get_interfaces_new_showiface(self):
        self._get.return_value = """<Response stat="200" code="ok"> <Success> <Data> <Interface> <Id>0</Id> <IPAddress>10.35.14.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>yes</GeoTrafficEnable> <DefaultInterface>yes</DefaultInterface> <AdminWuiEnable>yes</AdminWuiEnable> </Interface> <Interface> <Id>1</Id> <IPAddress>10.35.15.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>no</GeoTrafficEnable> <DefaultInterface>no</DefaultInterface> <AdminWuiEnable>no</AdminWuiEnable> </Interface> </Data> </Success> </Response>"""
        actual = self.lm.get_interfaces()
        expected_iface_eth0 = Interface(self.lm.access_info, 0)
        expected_iface_eth0.address = "10.35.14.5"
        expected_iface_eth0.cidr = "24"
        expected_iface_eth1 = Interface(self.lm.access_info, 1)
        expected_iface_eth1.address = "10.35.15.5"
        expected_iface_eth1.cidr = "24"
        expected = [expected_iface_eth0, expected_iface_eth1]
        assert_equal(len(expected), len(actual))
        for expected_iface, actual_iface in zip(expected, actual):
            assert_equal(expected_iface.addr, actual_iface.addr)

    def test_get_interfaces_new_showiface_unset_iface_bug(self):
        # Check does get_interfaces null duplicate interface IPs correctly
        self._get.return_value = """<Response stat="200" code="ok"> <Success> <Data> <Interface> <Id>0</Id> <IPAddress>10.35.14.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>yes</GeoTrafficEnable> <DefaultInterface>yes</DefaultInterface> <AdminWuiEnable>yes</AdminWuiEnable> </Interface> <Interface> <Id>1</Id> <IPAddress>10.35.14.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>no</GeoTrafficEnable> <DefaultInterface>no</DefaultInterface> <AdminWuiEnable>no</AdminWuiEnable> </Interface> </Data> </Success> </Response>"""
        actual = self.lm.get_interfaces()
        expected_iface_eth0 = Interface(self.lm.access_info, 0)
        expected_iface_eth0.address = "10.35.14.5"
        expected_iface_eth0.cidr = "24"
        expected = [expected_iface_eth0]
        assert_equal(len(expected), len(actual))
        for expected_iface, actual_iface in zip(expected, actual):
            assert_equal(expected_iface.addr, actual_iface.addr)

    def test_get_interfaces_when_new_showiface_doesnt_exist(self):
        stats_resp = """<Response stat="200" code="ok"> <Success> <Data> <CPU> <total> <User>0</User> <System>1</System> <Idle>99</Idle> <IOWaiting>0</IOWaiting> </total> <cpu0> <User>0</User> <System>1</System> <HWInterrupts>0</HWInterrupts> <SWInterrupts>0</SWInterrupts> <Idle>99</Idle> <IOWaiting>0</IOWaiting> </cpu0> <cpu1> <User>0</User> <System>1</System> <HWInterrupts>0</HWInterrupts> <SWInterrupts>0</SWInterrupts> <Idle>99</Idle> <IOWaiting>0</IOWaiting> </cpu1> </CPU> <Memory> <memused>300528</memused> <percentmemused>14</percentmemused> <memfree>1756204</memfree> <percentmemfree>86</percentmemfree> </Memory> <Network> <eth0> <ifaceID>0</ifaceID> <speed>1000</speed> <in>0.0</in> <inbytes>113</inbytes> <inbytesTotal>34664393</inbytesTotal> <out>0.0</out> <outbytes>86</outbytes> <outbytesTotal>33503963</outbytesTotal> </eth0> <eth1> <ifaceID>1</ifaceID> <speed>1000</speed> <in>0.0</in> <inbytes>0</inbytes> <inbytesTotal>900</inbytesTotal> <out>0.0</out> <outbytes>0</outbytes> <outbytesTotal>2844</outbytesTotal> </eth1> </Network> <TPS> <Total>0</Total> <SSL>0</SSL> </TPS> <VStotals> <ConnsPerSec>0</ConnsPerSec> <TotalConns>0</TotalConns> <BitsPerSec>0</BitsPerSec> <TotalBits>0</TotalBits> <BytesPerSec>0</BytesPerSec> <TotalBytes>0</TotalBytes> <PktsPerSec>0</PktsPerSec> <TotalPackets>0</TotalPackets> </VStotals> <Vs> <VSAddress>10.35.14.200</VSAddress> <VSPort>80</VSPort> <VSProt>tcp</VSProt> <Index>1</Index> <ErrorCode>0</ErrorCode> <Enable>1</Enable> <TotalConns>0</TotalConns> <TotalPkts>0</TotalPkts> <TotalBytes>0</TotalBytes> <TotalBits>0</TotalBits> <ActiveConns>0</ActiveConns> <BytesRead>0</BytesRead> <BytesWritten>0</BytesWritten> <ConnsPerSec>0</ConnsPerSec> <WafEnable>0</WafEnable> </Vs> <Rs> <VSIndex>1</VSIndex> <RSIndex>1</RSIndex> <Addr>10.35.14.7</Addr> <Port>80</Port> <Enable>1</Enable> <Weight>1000</Weight> <ActivConns>0</ActivConns> <Persist>0</Persist> <Conns>0</Conns> <Pkts>0</Pkts> <Bytes>0</Bytes> <Bits>0</Bits> <BytesRead>0</BytesRead> <BytesWritten>0</BytesWritten> <ConnsPerSec>0</ConnsPerSec> </Rs> </Data> </Success> </Response>"""
        showiface0_resp = """<Response stat="200" code="ok"> <Success> <Data> <Interface> <Id>0</Id> <IPAddress>10.35.14.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>yes</GeoTrafficEnable> <DefaultInterface>yes</DefaultInterface> <AdminWuiEnable>yes</AdminWuiEnable> </Interface> </Data> </Success> </Response>"""
        showiface1_resp = """<Response stat="200" code="ok"> <Success> <Data> <Interface> <Id>1</Id> <IPAddress>10.35.15.5/24</IPAddress> <Mtu>1500</Mtu> <InterfaceType>Port</InterfaceType> <GeoTrafficEnable>no</GeoTrafficEnable> <DefaultInterface>no</DefaultInterface> <AdminWuiEnable>no</AdminWuiEnable> </Interface> </Data> </Success> </Response>"""
        ex = exceptions.KempTechApiException()
        ex.status_code = 422
        self._get.side_effect = [ex, stats_resp, showiface0_resp, showiface1_resp]
        actual = self.lm.get_interfaces()
        expected_iface_eth0 = Interface(self.lm.access_info, 0)
        expected_iface_eth0.address = "10.35.14.5"
        expected_iface_eth0.cidr = "24"
        expected_iface_eth1 = Interface(self.lm.access_info, 1)
        expected_iface_eth1.address = "10.35.15.5"
        expected_iface_eth1.cidr = "24"
        expected = [expected_iface_eth0, expected_iface_eth1]
        assert_equal(len(expected), len(actual))
        for expected_iface, actual_iface in zip(expected, actual):
            assert_equal(expected_iface.addr, actual_iface.addr)

    def test_get_interfaces_raises_non_422_exceptions(self):
        ex = exceptions.KempTechApiException()
        ex.status_code = 401
        self._get.side_effect = ex
        with assert_raises(exceptions.KempTechApiException):
            actual = self.lm.get_interfaces()

    def test_get_interfaces_if_stats_fails_raise_exception(self):
        ex = exceptions.KempTechApiException()
        ex2 = exceptions.KempTechApiException()
        ex.status_code = 422
        self._get.side_effect = [ex, ex2]
        actual = self.lm.get_interfaces()
        expected = []
        assert_equal(actual, expected)
