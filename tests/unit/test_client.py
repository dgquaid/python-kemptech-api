import requests
from nose.tools import (assert_equal, assert_is_instance, assert_raises,
   assert_false, assert_in)

import python_kemptech_api.generic
import python_kemptech_api.models
import python_kemptech_api.objects
from python_kemptech_api import api_xml
from python_kemptech_api import generic

try:
    import unittest.mock as mock
except ImportError:
    import mock

mock_open = mock.mock_open
patch = mock.patch
MagicMock = mock.MagicMock
sentinel = mock.sentinel
PropertyMock = mock.PropertyMock

from requests import exceptions

import python_kemptech_api.client as client
from python_kemptech_api import utils

LoadMaster = python_kemptech_api.models.LoadMaster

class MyError(Exception):
    pass


class Test_HttpClient_as_context_manager:

    def test_context_manager_enter(self):
        with python_kemptech_api.generic.HttpClient() as aclient:
            assert_is_instance(aclient, python_kemptech_api.generic.HttpClient)

    def test_context_manager_exit(self):
        with assert_raises(MyError):
            with python_kemptech_api.generic.HttpClient():
                raise MyError('An Error')


class Test_HttpClient_do_request:

    def setup(self):
        self.p_Session = patch.object(generic, 'Session')
        Session = self.p_Session.start()
        self.p_requests = patch.object(generic, 'requests')
        rquests = self.p_requests.start()
        Session.return_value = rquests

        self.response = MagicMock()
        self.response.status_code = 200
        self.response.text = sentinel.response_text
        self.request = rquests.request
        self.request.return_value = self.response

        self.client = python_kemptech_api.generic.HttpClient()
        self.client.endpoint = 'ep/'

    def teardown(self):
        self.p_Session.stop()
        self.p_requests.stop()

    def test_no_file_parameter_set(self):
        open_ = mock_open(read_data='myData')
        with patch.object(client, "open", open_, create=True): # as my_open:
           self.client._do_request('GET','MyCommand')
           args = self.request.call_args
           # check positional arguments
           assert_equal(args[0], ('GET', 'ep/MyCommand?'))
           # check kwargs
           kw = args[1]
           assert_equal(kw['verify'], False)
           assert_equal(kw['params'], None)
           assert_false('data' in kw)

    def test_file_parameter_set(self):
        open_ = mock_open(read_data='myData')
        with patch.object(generic, "open", open_, create=True): # as my_open:
           self.client._do_request('GET','MyCommand',
                                                parameters=sentinel.params,
                                                file='my_filename')
           args = self.request.call_args
           # check positional arguments
           assert_equal(args[0], ('GET', 'ep/MyCommand?'))
           # check kwargs
           kw = args[1]
           assert_equal(kw['params'], sentinel.params)
           assert_in('data', kw)

    def test_400_status_code(self):
        self.response.status_code = 400
        res = self.client._do_request('GET','MyCommand')
        assert_equal(res, sentinel.response_text)

    def test_401_status_code(self):
        with assert_raises(client.KempTechApiException):
            self.response.status_code = 401
            self.response.text = "my error text"
            self.client._do_request('GET','MyCommand')

    # we test all the exceptions to confirm no errors will arise is their
    # call

    def test_re_raised_exceptions(self):
        my_exceptions = (exceptions.ConnectionError,
                                     exceptions.URLRequired,
                                     exceptions.TooManyRedirects,
                                     exceptions.Timeout,
                                     exceptions.RequestException)
        for e in my_exceptions:
            self.response.raise_for_status.side_effect = e
            with assert_raises(e):
                self.client._do_request('GET','MyCommand')

    def test_ConnectionTimeoutException(self):
        self.response.raise_for_status.side_effect = \
                exceptions.ConnectTimeout
        with assert_raises(client.ConnectionTimeoutException):
            self.client._do_request('GET','MyCommand')

    def test_HttpError(self):
        # this raises a KempTechApiException, whose
        # constructor expects an xml message, so we have
        # to choose a careful path through
        #  KempTechApiException.__init__

        self.response.text = None
        self.response.status_code = 999

        self.response.raise_for_status.side_effect = \
                exceptions.HTTPError
        with assert_raises(client.KempTechApiException):
            self.client._do_request('GET','MyCommand')


class Test_LoadMaster:

    def test_build_virtual_server(self):
        lm = python_kemptech_api.models.LoadMaster('ip', 'username', 'password')
        lm.ip_address = "1.1.1.1"
        with patch.object(LoadMaster,'endpoint', new_callable=PropertyMock) as mock_endpoint:
            mock_endpoint.return_value =  "https://bal:2fourall@1.1.1.1:443/access"

        service= {'VSPort': 80,
                  'Protocol': 'TCP',
                  'VSAddress': '1.1.1.1'}
        with patch.object(api_xml, 'get_data') as get_data:
            get_data.return_value = {}
            res = lm.build_virtual_service(service, "not none")
        assert_is_instance(res, client.VirtualService)

    def test__get_curl_command_list(self):
        lm = client.LoadMaster('ip', 'username', 'password')
        expected = ['curl', '-s', '-k', '--connect-timeout', str(utils.TIMEOUT),
                    'https://username:password@ip:443/access/test']
        actual = lm._get_curl_command_list("test")
        assert_equal(expected, actual)

    def test__get_curl_command_list_with_cert(self):
        lm = client.LoadMaster('ip', cert="./some/path")
        expected = ['curl', '-s', '-k', '--connect-timeout', str(utils.TIMEOUT),
                    '-E', './some/path', 'https://ip:443/access/test']
        actual = lm._get_curl_command_list("test")
        assert_equal(expected, actual)


class Test_KempBaseObjectModel:

    def test_to_api_dict(self):
        loadmaster_access = {
            "endpoint": "https://bal:1fourall@1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
        }

        kbom = python_kemptech_api.generic.BaseKempObject(loadmaster_access)
        kbom.none = None
        kbom.real_one = 'real'
        kbom._underscore = 'not wanted'
        res = kbom.to_api_dict()
        assert_equal(res, {'real_one': 'real'})
