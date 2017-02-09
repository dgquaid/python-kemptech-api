import json
import logging

import requests
from requests import exceptions, Session

from python_kemptech_api import utils
from .api_xml import (
    is_successful,
    get_data,
    get_error_msg)
from .exceptions import (
    KempTechApiException,
    ConnectionTimeoutException,
    GenericObjectMissingLoadMasterInfo,
    UnauthorizedAccessError)
from .utils import UseTlsAdapter, send_response


requests.packages.urllib3.disable_warnings()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
logging.basicConfig()


class HttpClient(object):
    """Client that performs HTTP requests."""

    ip_address = None
    endpoint = None

    def __init__(self, tls_version=utils.DEFAULT_TLS_VERSION, cert=None):
        self.cert = cert
        self._tls_version = tls_version
        self._tls_session = Session()
        self._tls_session.mount("http://", UseTlsAdapter(self._tls_version))

        self._retry_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._tls_session.close()
        return False

    def _do_request(self, http_method, rest_command,
                    parameters=None, file=None, data=None,
                    headers=None, retries=0):
        """Perform a HTTP request.

        :param http_method: GET or POST.
        :param rest_command: The command to run.
        :param parameters: dict containing parameters.
        :param file: Location of file to send.
        :return: The Status code of request and the response text body.
        """

        cmd_url = "{endpoint}{cmd}?".format(endpoint=self.endpoint,
                                            cmd=rest_command)

        log.debug(cmd_url)
        log.debug(repr(parameters))

        try:
            if file is not None:
                with open(file, 'rb') as payload:
                    response = self._tls_session.request(http_method, cmd_url,
                                                         params=parameters,
                                                         verify=False,
                                                         data=payload,
                                                         headers=headers,
                                                         cert=self.cert)
            else:
                response = self._tls_session.request(http_method,
                                                     cmd_url,
                                                     params=parameters,
                                                     data=data,
                                                     timeout=utils.TIMEOUT,
                                                     verify=False,
                                                     headers=headers,
                                                     cert=self.cert)
            self._tls_session.close()

            # Raise specific error for authentication failure
            if response.status_code == 401:
                log.warning("Cannot authenticate to %s check that the "
                            "credentials are correct.", self.ip_address)
                raise UnauthorizedAccessError(self.ip_address,
                                              response.status_code)

            # Raise generic error for other API failures
            if 400 < response.status_code < 500:
                raise KempTechApiException(msg=response.text,
                                           code=response.status_code)
            else:
                response.raise_for_status()
        except exceptions.ConnectTimeout:
            log.error("The connection timed out to %s.",
                      self.ip_address)
            raise ConnectionTimeoutException(self.ip_address)
        except (exceptions.ReadTimeout, exceptions.ConnectionError) as e:
            if retries < self._retry_count:
                log.warning("A %s occurred to %s.", e.__class__.__name__,
                            self.ip_address)
                return self._do_request(http_method,
                                        rest_command,
                                        parameters,
                                        file,
                                        retries + 1)
            else:
                log.warning("A repeated %s occurred to %s.",
                            e.__class__.__name__, self.ip_address)
                raise
        except exceptions.URLRequired:
            log.error("%s is an invalid URL", cmd_url)
            raise
        except exceptions.TooManyRedirects:
            log.error("Too many redirects with request to %s.", cmd_url)
            raise
        except exceptions.Timeout:
            log.error("A connection %s has timed out.", self.ip_address)
            raise
        except exceptions.HTTPError:
            log.error("A HTTP error occurred with request to %s.", cmd_url)
            raise KempTechApiException(msg=response.text,
                                       code=response.status_code)
        except exceptions.RequestException:
            log.error("An error occurred with request to %s.", cmd_url)
            raise

        return response.text

    def _get(self, rest_command, parameters=None, headers=None):
        return self._do_request('GET', rest_command, parameters,
                                headers=headers)

    def _post(self, rest_command, file=None, parameters=None, headers=None, data=None):
        return self._do_request('POST', rest_command, parameters=parameters,
                                file=file, data=data)


class AccessInfoMixin(object):
    endpoint = None
    ip_address = None
    cert = None

    @property
    def access_info(self):
        info = {
            "endpoint": self.endpoint,
            "ip_address": self.ip_address,
            "cert": self.cert,
            "appliance": self
        }
        return info


class BaseKempObject(HttpClient, AccessInfoMixin):
    _API_ADD = ""
    _API_MOD = ""
    _API_DELETE = ""
    _API_GET = ""
    _API_LIST = ""
    API_TAG = ""
    API_INIT_PARAMS = {}
    _API_BASE_PARAMS = {}
    _API_DEFAULT_ATTRIBUTES = {}

    # Blacklist attributes that shouldn't be pushed to the loadmaster.
    _API_IGNORE = (
        "log_urls", "ip_address", "endpoint", "rsindex", "vsindex", "index",
        "status", "subvs_data", "subvs_entries", "real_servers", "cert",
        "checkuse1_1", "mastervsid", "API_INIT_PARAMS", "API_TAG"
    )

    def __init__(self, loadmaster_info, **kwargs):
        try:
            self.endpoint = loadmaster_info["endpoint"]
        except KeyError:
            raise GenericObjectMissingLoadMasterInfo(type(self), "endpoint")

        try:
            self.ip_address = loadmaster_info["ip_address"]
        except KeyError:
            raise GenericObjectMissingLoadMasterInfo(type(self), "ip_address")

        super(BaseKempObject, self).__init__(loadmaster_info)

    def __repr__(self):
        return '{} {}'.format(
            self.__class__.__name__,
            json.dumps(self.to_dict()))

    def _is_successful_or_raise(self, response):
        if is_successful(response):
            data = get_data(response)
            self.populate_default_attributes(data)
        else:
            raise KempTechApiException(get_error_msg(response))

    @property
    def access_info(self):
        info = super(BaseKempObject, self).access_info
        info.update(self._get_base_parameters())
        return info

    def save(self, update=False):
        if not update:
            response = self._get(self._API_ADD, self.to_api_dict())
        else:
            response = self._get(self._API_MOD, self.to_api_dict())

        self._is_successful_or_raise(response)

    def update(self):
        self.save(update=True)

    def refresh(self):
        response = self._get(
            self._API_GET,
            self._get_base_parameters())
        xml_object = get_data(response)
        # Again line below will fail with ValidationError if
        # empty responselm.
        self.populate_default_attributes(xml_object)

    def delete(self):
        response = self._get(self._API_DELETE, self._get_base_parameters())
        return send_response(response)

    def to_api_dict(self):
        """Returns API related attributes as a dict

        Ignores attributes listed in _api_ignore and also attributes
        beginning with an underscore (_). Also ignore values of None"""
        api_dict = {}
        for key, value in self.__dict__.items():
            if (key in self._API_IGNORE or key.startswith("_") or
                    value is None):
                continue
            api_dict[key] = value
        return api_dict

    def to_dict(self):
        """returns attributes whose values are not None or whose name starts
        with _ as a dict"""
        api_dict = {}
        for key, value in self.__dict__.items():
            if key.startswith("_") or value is None:
                continue
            api_dict[key] = value
        return api_dict

    def _get_base_parameters(self):
        """Returns the bare minimum parameters."""
        base_parameters = {}
        for parameter in self._API_BASE_PARAMS:
            base_parameters[parameter] = self.__getattribute__(parameter)
        return base_parameters

    def populate_default_attributes(self, params):
        """Populate object instance with standard defaults"""
        if len(params) == 0:
            log.warning("No data was returned, leaving data intact")
            return

        if len(params) == 1:
            if self.API_TAG in params.keys():
                self.populate_default_attributes(params[self.API_TAG])
                return

        for attribute, tag in self._API_DEFAULT_ATTRIBUTES.items():
            setattr(self, attribute, params.get(tag, None))
