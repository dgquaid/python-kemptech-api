from .api_xml import get_error_msg


STATUS_CODES = {
    400: 'Mandatory parameter missing from request',
    401: 'Client Error: Authorization required',
    403: 'Incorrect permissions',
    404: 'Not found. Ensure the API is enabled on the LoadMaster',
    405: 'Unknown command',
    422: 'Invalid operation'
}


def get_api_exception_message(msg, code, is_xml_msg):
    if msg is not None:
        # 400 Errors should be handled here. This will pass the error
        # message given by the LoadMaster API and show it as the exception
        # message in the traceback.
        message = get_error_msg(msg) if is_xml_msg else msg
    else:
        try:
            message = '{} {}.'.format(code, STATUS_CODES[code])
        except KeyError:
            message = "An unknown error has occurred ({}).".format(code)

    return message


class KempTechApiException(Exception):
    """Raised if HTTP request has failed."""

    def __init__(self, msg=None, code=None, is_xml_msg=True):
        self.status_code = code
        message = get_api_exception_message(msg, code, is_xml_msg)
        super(KempTechApiException, self).__init__(message)


class KempConnectionError(KempTechApiException):
    def __init__(self, endpoint, code=None):
        msg = "A connection error occurred to {endpoint}."\
            .format(endpoint=endpoint)
        super(KempConnectionError, self).__init__(msg, code=code)


class UnauthorizedAccessError(KempTechApiException):
    def __init__(self, cmd_url, code=None):
        msg = "You do not have authorized access to {}. " \
              "Please check your credentials.".format(cmd_url)
        super(UnauthorizedAccessError, self).__init__(msg, code=code,
                                                      is_xml_msg=False)


class UrlRequiredError(KempTechApiException):
    def __init__(self, cmd_url, code=None):
        msg = "{} is an invalid URL".format(cmd_url)
        super(UrlRequiredError, self).__init__(msg, code=code)


class TooManyRedirectsException(KempTechApiException):
    def __init__(self, cmd_url, code=None):
        msg = "Too many redirects with request to {}.".format(cmd_url)
        super(TooManyRedirectsException, self).__init__(msg, code=code)


class TimeoutException(KempTechApiException):
    def __init__(self, endpoint, code=None):
        msg = "A connection {} has timed out.".format(endpoint)
        super(TimeoutException, self).__init__(msg, code=code)


class HTTPError(KempTechApiException):
    def __init__(self, cmd_url, code=None):
        msg = "A HTTP error occurred with request to {}.".format(cmd_url)
        super(HTTPError, self).__init__(msg, code=code)


class ApiNotEnabledError(KempTechApiException):
    def __init__(self, code=None):
        msg = "Ensure the API is enabled on the LoadMaster."
        super(ApiNotEnabledError, self).__init__(msg, code=code)


class CommandNotAvailableException(KempTechApiException):
    def __init__(self, lm, cmd_name, code=None):
        msg = "Command '{}' is not available on LoadMaster {}.".format(
            cmd_name, lm)
        super(CommandNotAvailableException, self).__init__(msg,
                                                           is_xml_msg=False,
                                                           code=code)


class ConnectionTimeoutException(KempTechApiException):
    def __init__(self, lm, code=None):
        msg = "Connection timed out to '{}'.".format(lm)
        super(ConnectionTimeoutException, self).__init__(
            msg, is_xml_msg=False, code=code)


def get_parameter_message(obj, parameters):
    try:
        param = parameters['param']
        value = parameters['value']
        msg = '{} failed to set {}: {}'.format(obj, param, value)
    except (KeyError, TypeError) as e:
        msg = '{} failed to set {} ({})'.format(
            obj, parameters, str(e))

    return msg


class ValidationError(Exception):
    pass


class LoadMasterParameterError(Exception):
    def __init__(self, lm, parameters):
        msg = get_parameter_message(lm, parameters)
        super(LoadMasterParameterError, self).__init__(msg)


class VirtualServiceParameterError(Exception):
    def __init__(self, vs, parameters):
        msg = get_parameter_message(vs, parameters)
        super(VirtualServiceParameterError, self).__init__(msg)


class RealServerParameterError(Exception):
    def __init__(self, rs, parameters):
        msg = get_parameter_message(rs, parameters)
        super(RealServerParameterError, self).__init__(msg)


class SubVsCannotCreateSubVs(Exception):
    def __init__(self):
        msg = "A sub virtual service cannot create a sub virtual service"
        super(SubVsCannotCreateSubVs, self).__init__(msg)


class MissingInfo(Exception):
    service = 'My service'
    param_name = 'parameter_name'

    def __init__(self, param):
        msg = ("{} is missing the {} parameter "
               "'{}'").format(self.service, self.param_name, param)
        super(MissingInfo, self).__init__(msg)


class GenericObjectMissingLoadMasterInfo(MissingInfo):
    def __init__(self, service, param):
        self.service = service
        self.param_name = "LoadMaster"
        super(GenericObjectMissingLoadMasterInfo, self).__init__(param)


class VirtualServiceMissingLoadmasterInfo(MissingInfo):
    service = 'Virtual service'
    param_name = 'LoadMaster'


class RealServerMissingLoadmasterInfo(MissingInfo):
    service = 'Real server'
    param_name = 'LoadMaster'


class RealServerMissingVirtualServiceInfo(MissingInfo):
    service = 'Real server'
    param_name = 'Virtual service'


class BackupFailed(KempTechApiException):
    def __init__(self, ip_address, code=None):
        msg = ("Failed to create a backup. Could not reach LoadMaster {}."
               .format(ip_address))
        super(BackupFailed, self).__init__(msg, code=code, is_xml_msg=False)


class DownloadUserCertFailed(KempTechApiException):
    def __init__(self, ip_address, code=None):
        msg = ("Failed to download user cert. Could not reach LoadMaster {}."
               .format(ip_address))
        super(DownloadUserCertFailed, self).__init__(msg, code=code)


class UserAlreadyExistsException(KempTechApiException):
    def __init__(self, user, ip_address, code=None):
        msg = ("User '{}' already exists on LoadMaster {}."
               .format(user, ip_address))
        super(UserAlreadyExistsException, self).__init__(msg, code=code,
                                                         is_xml_msg=False)


class NotVirtualServiceInstanceError(KempTechApiException):
    def __init__(self, code=None):
        msg = ("The object you are trying to clone is "
               "not an instance of VirtualService.")
        super(NotVirtualServiceInstanceError, self).__init__(msg, code=code)


class VirtualServiceACLMissingVirtualServiceInfo(MissingInfo):
    service = 'VirtualServiceACL'
    param_name = 'Virtual service'


class TemplateMissingLoadmasterInfo(MissingInfo):
    service = 'Template'
    param_name = 'LoadMaster'


class CertificateMissingLoadmasterInfo(MissingInfo):
    service = 'Certificate'
    param_name = 'LoadMaster'


class RuleMissingLoadmasterInfo(MissingInfo):
    service = 'Rule'
    param_name = 'LoadMaster'


class FqdnMissingLoadmasterInfo(MissingInfo):
    service = 'Fqdn'
    param_name = 'LoadMaster'


class SiteMissingFQDNInfo(MissingInfo):
    service = 'Site'
    param_name = 'FQDN'


class SiteMissingLoadmasterInfo(MissingInfo):
    service = 'Site'
    param_name = 'LoadMaster'


class ClusterMissingLoadmasterInfo(MissingInfo):
    service = 'Cluster'
    param_name = 'LoadMaster'


class RangeMissingLoadmasterInfo(MissingInfo):
    service = 'Range'
    param_name = 'LoadMaster'


class RangeMaskInvalid(ValidationError):
    def __init__(self, mask):
        msg = "Specified netmask is invalid. Mask must be between 8-32"
        super(RangeMaskInvalid, self).__init__(msg)


class CipherListInvalid(ValidationError):
    def __init__(self, ciphers):
        msg = "Specified cipher list is invalid. Must be either a list or a "\
              "string in the cipher list format"
        super(CipherListInvalid, self).__init__(msg)
