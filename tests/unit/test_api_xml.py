import os

from nose.tools import assert_equal, assert_is_none

# handle py3 and py2 cases:
try:
    import unittest.mock as mock
except ImportError:
    import mock

patch = mock.patch
sentinel = mock.sentinel

import xmltodict

import python_kemptech_api.api_xml as api_xml
from bin.conf import XML_DATA_DIR


def test_is_successful_str():
    with patch.object(api_xml,'get_success_msg') as get_success_msg:
        get_success_msg.return_value = 'any string'
        res = api_xml.is_successful('any_xml')
        assert_equal(res, True)


def test_is_successful_None():
    with patch.object(api_xml,'get_success_msg') as get_success_msg:
        get_success_msg.return_value =None
        res = api_xml.is_successful('any_xml')
        assert_equal(res, False)


def test_get_xml_field_no_data_field():
    with patch.object(api_xml,'xmltodict') as xmltodict:
        xmltodict.parse.return_value = {'Response':{'myfield': 'myfield-value'}}
        res = api_xml._get_xml_field('any_xml', 'myfield')
        assert_equal(res, 'myfield-value')


def test_get_xml_field_with_data_field():
    with patch.object(api_xml,'xmltodict') as xmltodict:
        xmltodict.parse.return_value = {
        'Response':{'Success': {'myfield': {
             'mydata': 'mydata-value'}}}}
        res = api_xml._get_xml_field('any_xml', 'myfield', 'mydata')
        assert_equal(res, 'mydata-value')

def test_get_xml_field_with_KeyError():
    with patch.object(api_xml,'xmltodict') as xmltodict:
        xmltodict.parse.return_value = {}
        res = api_xml._get_xml_field('any_xml', 'myfield')
        assert_equal(res, {})

def test_get_data_ok():
    with patch.object(api_xml, '_get_xml_field') as _get_xml_field:
        _get_xml_field.return_value = {'Data': sentinel.data}
        res = api_xml.get_data('anyxml')
        assert_equal(sentinel.data, res)

def test_get_data_no_Data_key():
    with patch.object(api_xml, '_get_xml_field') as _get_xml_field:
        _get_xml_field.return_value = {'junk': 'anything'}
        res = api_xml.get_data('anyxml')
        assert_equal(res, {})

def test_get_xml_field_ExpatError_returns_empty_dict():
    with patch.object(xmltodict, "parse") as parse:
        parse.side_effect = xmltodict.expat.ExpatError
        actual = api_xml._get_xml_field('any_xml', 'myfield')
        assert_equal(actual, {})

def test_get_success_msg():
    with patch.object(api_xml, '_get_xml_field') as _get_xml_field:
        _get_xml_field.return_value = {'Success': sentinel.data}
        res = api_xml.get_success_msg('anyxml')
        assert_equal("{'Success': sentinel.data}", res)

def test_get_error_msg():
    with patch.object(api_xml, '_get_xml_field') as _get_xml_field:
        _get_xml_field.return_value = {'Error': sentinel.data}
        res = api_xml.get_error_msg('anyxml')
        assert_equal("{'Error': sentinel.data}", res)

def test_get_data_field():
    with patch.object(api_xml, '_get_xml_field') as _get_xml_field:
        _get_xml_field.return_value = {'Data': sentinel.data}
        res = api_xml.get_data_field('any_xml', 'any_field')
        assert_equal({'Data': sentinel.data}, res)
