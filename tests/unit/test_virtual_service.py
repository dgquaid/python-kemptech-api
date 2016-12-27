from nose.tools import (assert_equal, assert_raises, assert_in,
                        assert_is_instance, assert_not_equal)

# handle py3 and py2 cases:
try:
    import unittest.mock as mock
except ImportError:
    import mock

patch = mock.patch
sentinel = mock.sentinel

from python_kemptech_api import objects
import python_kemptech_api.exceptions as exceptions
from python_kemptech_api.objects import VirtualService, RealServer

ValidationError = exceptions.ValidationError


class Test_VirtualService:

    def setup(self):
        self.lm_info = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }
        self.vs = VirtualService(self.lm_info, "1.1.1.2")
        # Contains no subvs's
        self.vs_get_response = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> </Data> </Success> </Response>"
        # Contains default cert
        self.vs_get_response_defaultcert = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> <SSLAcceleration>Y</SSLAcceleration> <CertFile>f5d7b5869a48de4e30930785dcff3657</CertFile> </Data> </Success> </Response>"
        # Contains one cert
        self.vs_get_response_singlecert = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> <SSLAcceleration>Y</SSLAcceleration> <CertFile>cert1</CertFile> </Data> </Success> </Response>"
        # Contains multiple certs
        self.vs_get_response_multicert = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> <SSLAcceleration>Y</SSLAcceleration> <CertFile>cert1 cert2 cert3 cert4</CertFile> </Data> </Success> </Response>"

        # real server 'get'
        self.rs_get_response = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Rs> <Status>Down</Status> <VSIndex>0</VSIndex> <RsIndex>1</RsIndex> <Addr>10.154.123.13</Addr> <Port>80</Port> <Forward>nat</Forward> <Weight>1000</Weight> <Limit>0</Limit> <Enable>Y</Enable> <Critical>N</Critical> </Rs> </Data> </Success> </Response>"
        # A 'get' of a subvs
        self.subvs_get_response = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>2</Index> <VSPort>0</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditnone</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>1</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> </Data> </Success> </Response>"
        # A parent vs with a subvs newly created
        self.create_subvs_get_response = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>1</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <RsMinimum>0</RsMinimum> <NumberOfRSs>1</NumberOfRSs> <SubVS> <Status>Down</Status> <VSIndex>2</VSIndex> <RsIndex>1</RsIndex> <Name>-</Name> <Forward>nat</Forward> <Weight>1000</Weight> <Limit>0</Limit> <Enable>Y</Enable> <Critical>N</Critical> </SubVS> </Data> </Success> </Response>"

    def test_init_with_no_endpoint(self):
        lm_info_with_no_endpoint = {"ip_address": "1.1.1.1"}
        VirtualService(self.lm_info, "1.1.1.2")
        with assert_raises(exceptions.VirtualServiceMissingLoadmasterInfo):
            VirtualService(lm_info_with_no_endpoint, "1.1.1.2")

    def test_init_with_no_ipaddress(self):
        lm_info_with_no_ip_address = {"endpoint": "https://1.1.1.1:443/access"}
        VirtualService(self.lm_info, "1.1.1.2")
        with assert_raises(exceptions.VirtualServiceMissingLoadmasterInfo):
            VirtualService(lm_info_with_no_ip_address, "1.1.1.2")

    def test_str(self):
        assert_equal(str(self.vs), "Virtual Service TCP 1.1.1.2:80 on "
                                   "LoadMaster 1.1.1.1")

    def test_get_base_parameters(self):
        base_params = self.vs._get_base_parameters()
        expected_params = {
            "vs": "1.1.1.2",
            "port": 80,
            "prot": "tcp",
        }
        assert_equal(base_params, expected_params)

        self.vs.index = 1
        base_params = self.vs._get_base_parameters()
        expected_params = {
            "vs": 1,
        }
        assert_equal(base_params, expected_params)

    def test_to_api_dict(self):
        actual = self.vs.to_api_dict()
        expected = {
            "vs": "1.1.1.2",
            "port": 80,
            "prot": "tcp",
        }
        assert_equal(actual, expected)

    def test_to_dict(self):
        self.vs._ignore = None
        actual = self.vs.to_dict()
        expected = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "vs": "1.1.1.2",
            "port": 80,
            "prot": "tcp",
            "auth": ("bal", "2fourall"),
            "subvs_entries": [],
            "real_servers": [],
        }
        print(actual)
        assert_equal(actual, expected)

    def test_create_sub_virtual_service(self):
        sub_vs = self.vs.create_sub_virtual_service()
        actual = sub_vs._is_sub_vs
        expected = True
        assert_equal(actual, expected)

    def test_subvs_cant_create_sub_virtual_service(self):
        sub_vs = self.vs.create_sub_virtual_service()
        with assert_raises(exceptions.SubVsCannotCreateSubVs):
            sub_vs.create_sub_virtual_service()

    def test_vs_save_certfile_list(self):
        with patch.object(VirtualService, "_get") as _get:
            _get.return_value = self.vs_get_response_multicert
            self.vs.sslacceleration = "Y"
            self.vs.certfile = ["cert1", "cert2", "cert3", "cert4"]
            # use update=True to skip some code not in test for this case
            self.vs.save(update=True)
            expected = ["cert1", "cert2", "cert3", "cert4"]
            actual = self.vs.certfile
            assert_equal(actual, expected)

    def test_vs_save_certfile_str(self):
        with patch.object(VirtualService, "_get") as _get:
            _get.return_value = self.vs_get_response_singlecert
            print(self.vs.__repr__())
            self.vs.sslacceleration = "Y"
            self.vs.certfile = "cert1"
            # use update=True to skip some code not in test for this case
            self.vs.save(update=True)
            print(self.vs.__repr__())
            expected = ["cert1"]
            actual = self.vs.certfile
            assert_equal(actual, expected)

    def test_vs_save_certfile_None(self):
        with patch.object(VirtualService, "_get") as _get:
            _get.return_value = self.vs_get_response_defaultcert
            self.vs.sslacceleration = "N"
            self.vs.certfile = ""
            # use update=True to skip some code not in test for this case
            self.vs.save(update=True)
            expected = []
            actual = self.vs.certfile
            assert_equal(actual, expected)

    def test_vs_save_persist(self):
        with patch.object(VirtualService, "_get") as _get:
            _get.return_value = self.vs_get_response
            self.vs.persist = None
            # use update=True to skip some code not in test for this case
            self.vs.save(update=True)
            expected = None
            actual = self.vs.persisttimeout
            assert_equal(actual, expected)

    def test_save_add_normal_vs(self):
        with patch.object(VirtualService, "_get") as _get:
            _get.return_value = self.vs_get_response
            expected = None
            actual = self.vs.index
            assert_equal(actual, expected)
            self.vs.save()
            expected = "1"
            actual = self.vs.index
            assert_equal(actual, expected)

    def test_save_add_sub_vs(self):
        with patch.object(VirtualService, "_get") as _get:
            # set the index to pretend the parent  vs has already been "saved"
            self.vs.index = 1
            subvs = self.vs.create_sub_virtual_service()
            _get.side_effect = [self.vs_get_response, self.create_subvs_get_response, self.subvs_get_response]
            # This will run through the big "Hell, thy name be subvs" block in VirtualService's save method
            subvs.save()
            expected = "2"
            actual = subvs.index
            assert_equal(actual, expected)
            expected = []
            actual = subvs.subvs_data
            assert_not_equal(actual, expected)

    def test_save_update_sub_vs(self):
        with patch.object(VirtualService, "_get") as _get:
            with patch.object(VirtualService, "_subvs_to_dict") as _subvs_to_dict:
                _subvs_to_dict.return_value = {
                    "vs": "1",
                    "rs": "!1",
                    "name": "asdf",
                    "forward": "asdf",
                    "weight": "sdf",
                    "limit": "sdf",
                    "critical": "sdf",
                    "enable": "sdf",
                }
                # set the index to pretend the parent  vs has already been "saved"
                self.vs.index = 1
                subvs = self.vs.create_sub_virtual_service()
                _get.return_value = self.subvs_get_response
                subvs.save(update=True)
                expected = "2"
                actual = subvs.index
                assert_equal(actual, expected)
                expected = []
                actual = subvs.subvs_data
                assert_not_equal(actual, expected)


class Test_get_real_servers:

    def setup(self):
        self.lm_info = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }
        self.vs = VirtualService(self.lm_info, "1.1.1.2")

    def test_data_exists(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data') as get_data:
                with patch.object(VirtualService, '_get'):
                    build_real_server.side_effect = sorted
                    get_data. return_value = {'Rs': ['ba', 'ed']}
                    res =  self.vs.get_real_servers()
        expected = [['a','b'], ['d','e']]
        assert_equal(res, expected)

    def test_no_data_exists(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data') as get_data:
                with patch.object(VirtualService, '_get'):
                    build_real_server.side_effect = sorted
                    get_data.return_value = {}
                    res = self.vs.get_real_servers()
        expected = []
        assert_equal(res, expected)


class Test_get_real_server:

    def setup(self):
        self.lm_info = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }
        self.vs = VirtualService(self.lm_info, "1.1.1.2")

    def test_with_index_ok(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data'):
                with patch.object(VirtualService, '_get'):
                    self.vs.index = self
                    build_real_server.return_value = sentinel.rs
                    res =  self.vs.get_real_server('1.1.1.1', 80)
        assert_equal(res, sentinel.rs)

    def test_with_index_invalid_port(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data'):
                with patch.object(VirtualService, '_get'):
                    self.vs.index = self
                    build_real_server.return_value = sentinel.rs
                    with assert_raises(ValidationError):
                        self.vs.get_real_server('1.1.1.1', 'junk')

    def test_without_index_ok(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data'):
                with patch.object(VirtualService, '_get'):
                    self.vs.index = None
                    build_real_server.return_value = sentinel.rs
                    res =  self.vs.get_real_server('1.1.1.1', 80)
        assert_equal(res, sentinel.rs)

    def test_without_index_invalid_port(self):
        with patch.object(VirtualService, 'build_real_server') as build_real_server:
            with patch.object(objects, 'get_data'):
                with patch.object(VirtualService, '_get'):
                    self.vs.index = None
                    build_real_server.return_value = sentinel.rs
                    with assert_raises(ValidationError):
                        self.vs.get_real_server('1.1.1.1.', 'junk')


class Test_build_real_server:

    def setup(self):
        self.lm_info = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }
        self.vs = VirtualService(self.lm_info, "1.1.1.2")

    def test_no_Addr(self):
        server = {"Port": 80}
        with assert_raises(ValidationError) as err:
            self.vs.build_real_server(server)
        assert_in('Addr', str(err.exception))

    def test_no_Port(self):
        server = {"Addr": '1.1.1.1'}
        with assert_raises(ValidationError) as err:
            self.vs.build_real_server(server)
        assert_in('Port', str(err.exception))

    def test_ok(self):
        server = {"Addr": '1.1.1.1', "Port": 80}
        res = self.vs.build_real_server(server)
        assert_is_instance(res, RealServer)
