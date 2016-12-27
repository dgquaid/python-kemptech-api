from nose.tools import (
    assert_raises,
    assert_is_none,
    assert_equal
    )

from python_kemptech_api.api_xml import get_data
from python_kemptech_api.models import LoadMaster
from python_kemptech_api.objects import VirtualService

try:
    import unittest.mock as mock
except ImportError:
    import  mock

mock_open = mock.mock_open
patch = mock.patch
MagicMock = mock.MagicMock
sentinel = mock.sentinel

from python_kemptech_api.utils import (
    validate_port,
    validate_ip,
    validate_protocol,
    falsey_to_none,
    list_object)
from python_kemptech_api.exceptions import (
    ValidationError
    )


class Test_validate_port:

    def test_ok(self):
        assert_is_none(validate_port('22'))

    def test_non_integer(self):
        with assert_raises(ValidationError):
            validate_port('sds')

    def test_out_of_range(self):
        with assert_raises(ValidationError):
            validate_port(1000000)

    def test_wildcard_port(self):
        expected = None
        actual = validate_port("*")
        assert_equal(expected, actual)


class Test_validate_ip:

    def test_ok(self):
        assert_is_none(validate_ip('2.2.2.2'))
        assert_is_none(validate_ip('2001:cdba::3257:9652'))

    def test_invalid_str(self):
        with assert_raises(ValidationError):
            validate_ip('sds')

    def test_none(self):
        with assert_raises(ValidationError):
            validate_ip(None)


class Test_validate_protocol:

    def test_TCP(self):
        assert_is_none(validate_protocol('TCP'))

    def test_udp(self):
        assert_is_none(validate_protocol('udp'))

    def test_invalid(self):
        with assert_raises(ValidationError):
            validate_protocol('sds')


def test_falsey_to_none():
    expected = None
    var = 0
    actual = falsey_to_none(var)
    assert_equal(expected, actual)


def test_list_object():
    lm = LoadMaster("1.1.1.1", "bal", "2fourall")
    vs = lm.create_virtual_service("1.1.1.2")
    response = "<Response stat=\"200\" code=\"ok\"> <Success> <Data> <VS> <Status>Down</Status> <Index>1</Index> <VSAddress>10.154.75.123</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> </VS> <VS> <Status>Down</Status> <Index>2</Index> <VSAddress>10.154.190.229</VSAddress> <VSPort>80</VSPort> <Enable>Y</Enable> <SSLReverse>N</SSLReverse> <SSLReencrypt>N</SSLReencrypt> <Intercept>N</Intercept> <InterceptOpts> <Opt>opnormal</Opt> <Opt>auditrelevant</Opt> <Opt>reqdatadisable</Opt> <Opt>resdatadisable</Opt> </InterceptOpts> <AlertThreshold>0</AlertThreshold> <Transactionlimit>0</Transactionlimit> <Transparent>Y</Transparent> <SubnetOriginating>N</SubnetOriginating> <ServerInit>0</ServerInit> <StartTLSMode>0</StartTLSMode> <Idletime>0</Idletime> <Cache>N</Cache> <Compress>N</Compress> <Verify>0</Verify> <UseforSnat>N</UseforSnat> <ForceL7>Y</ForceL7> <MultiConnect>N</MultiConnect> <ClientCert>0</ClientCert> <ErrorCode>0</ErrorCode> <CheckUse1.1>N</CheckUse1.1> <MatchLen>0</MatchLen> <CheckUseGet>0</CheckUseGet> <SSLRewrite>0</SSLRewrite> <VStype>http</VStype> <FollowVSID>0</FollowVSID> <Protocol>tcp</Protocol> <Schedule>rr</Schedule> <CheckType>http</CheckType> <PersistTimeout>0</PersistTimeout> <CheckPort>0</CheckPort> <NRules>0</NRules> <NRequestRules>0</NRequestRules> <NResponseRules>0</NResponseRules> <NPreProcessRules>0</NPreProcessRules> <EspEnabled>N</EspEnabled> <InputAuthMode>0</InputAuthMode> <OutputAuthMode>0</OutputAuthMode> <MasterVS>0</MasterVS> <MasterVSID>0</MasterVSID> <AddVia>0</AddVia> <QoS>0</QoS> <TlsType>0</TlsType> <NeedHostName>N</NeedHostName> <OCSPVerify>N</OCSPVerify> <EnhancedHealthChecks>N</EnhancedHealthChecks> <RsMinimum>0</RsMinimum> <NumberOfRSs>0</NumberOfRSs> </VS> </Data> </Success> </Response>"
    data = get_data(response)
    vss = list_object(VirtualService, vs.access_info, data)
    assert_equal(2,len(vss))
