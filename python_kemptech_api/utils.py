from ssl import PROTOCOL_TLSv1
TSL_v1 = PROTOCOL_TLSv1
DEFAULT_TLS_VERSION = PROTOCOL_TLSv1
try:
    from ssl import PROTOCOL_TLSv1_1
    TSL_v1_1 = PROTOCOL_TLSv1_1
except ImportError:
    TSL_v1_1 = DEFAULT_TLS_VERSION
try:
    from ssl import PROTOCOL_TLSv1_2
    DEFAULT_TLS_VERSION = PROTOCOL_TLSv1_2
    TSL_v1_2 = PROTOCOL_TLSv1_2
except ImportError:
    TSL_v1_2 = DEFAULT_TLS_VERSION

import sys

from netaddr import IPAddress, AddrFormatError
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

from python_kemptech_api.exceptions import (
    KempTechApiException,
    ValidationError)
from python_kemptech_api.api_xml import (
    is_successful,
    parse_to_dict,
    get_error_msg)


IS_PY3 = sys.version[0] == '3'
TIMEOUT = 5


def validate_port(port):
    try:
        p = int(port)
    except ValueError:
        if port == "*":
            # * is allowed for creating wildcard VSs
            return

        raise ValidationError('Port must be an integer ({} given)'
                              .format(port))

    if not 1 <= p <= 65535:
        raise ValidationError('Invalid port number ({} given)'.format(p))


def validate_ip(ip):
    try:
        IPAddress(ip)
    except AddrFormatError:
        raise ValidationError('Invalid IP address ({} given)'.format(ip))


def validate_protocol(protocol):
    if protocol.upper() not in ('TCP', 'UDP'):
        raise ValidationError('Invalid protocol ({} given)'.format(protocol))


class UseTlsAdapter(HTTPAdapter):

    tls_version = None

    def __init__(self, tls_version=None):
        if tls_version is None:
            self.tls_version = DEFAULT_TLS_VERSION
        self.tls_version = tls_version
        super(UseTlsAdapter, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize, block=block,
                                       ssl_version=self.tls_version)


def get_sub_vs_list_from_data(response_data):
    """Get Sub VS IDs and the "Rs" data portion of the Sub VSs as a tuple

    :param response_data: Data portion of LM API response
    :return: Tuple of list of sub VS IDs and a dict of full RS sub VS data
    """
    subvs_entries = []
    full_data = {}
    for key, value in response_data.items():
        if key == "SubVS":
            if isinstance(value, list):
                for subvs in value:
                    full_data[subvs['VSIndex']] = subvs
                    subvs_entries.append(subvs['VSIndex'])
            else:
                full_data[value['VSIndex']] = value
                subvs_entries.append(value['VSIndex'])
    return subvs_entries, full_data


def send_response(response):
    if is_successful(response):
        return parse_to_dict(response)
    else:
        raise KempTechApiException(get_error_msg(response))


def get_api_bool_string(api_bool):
    """Return KEMP restfull API version of a bool string"""
    return 'y' if api_bool else 'n'


def get_dict_entry_as_list(key, data):
    """Returns an entry from a dict as a list"""
    value = data.get(key, [])
    return cast_to_list(value)


def cast_to_list(data):
    """Cast data to a list if it is not already a list.

    :param data: The variable to be cast to a list.
    :return: The data in a list
    """
    if not isinstance(data, list):
        data = [data]
    return data


def falsey_to_none(var):
    """Certain parameters return invalid 0 when they should be False

    This function takes a variable, checks if its 'falsey' and return it
    with the value of None if it is.
    :param var: The variable to check
    :return: The variable that was given, with value of None if it was falsey
    """
    if not var:
        var = None
    return var


def build_object(class_to_build, access_info, data_for_instance):
    """Factory method that can can build instances of BaseKempObject

    :param class_to_build: Subclass of BaseKempObject
    :param access_info: Access info that will allow it to attach to parent
    :param data_for_instance: Default data for class instance
    :return: Instance of class populated with access info and default data
    """
    build_parameters = {}

    for parameter, tag in class_to_build.API_INIT_PARAMS.items():
        build_parameters[parameter] = data_for_instance.get(tag)

    obj = class_to_build(access_info, **build_parameters)
    obj.populate_default_attributes(data_for_instance)
    return obj


def list_object(class_to_list, access_info, data):
    xml_object = data.get(class_to_list.API_TAG, [])
    xml_object = cast_to_list(xml_object)

    obj_list = []

    for x in xml_object:
        obj = build_object(class_to_list, access_info, x)
        obj_list.append(obj)

    return obj_list
