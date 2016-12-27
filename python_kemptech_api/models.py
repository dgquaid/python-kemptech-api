import logging
import os
import time
import subprocess

from requests import exceptions

from python_kemptech_api import utils
from python_kemptech_api.api_xml import (
    get_data_field,
    is_successful,
    get_data,
    get_error_msg
)
from python_kemptech_api.capabilities import CAPABILITIES, DEFAULT
from python_kemptech_api.exceptions import (
    LoadMasterParameterError,
    KempTechApiException,
    BackupFailed,
    CommandNotAvailableException,
    UserAlreadyExistsException,
    DownloadUserCertFailed,
    NotVirtualServiceInstanceError
)
from python_kemptech_api.generic import HttpClient, AccessInfoMixin
from python_kemptech_api.objects import (
    VirtualService,
    CipherSet,
    Certificate,
    Sso,
    Rule,
    GlobalACL,
    Template,
    Fqdn,
    Cluster,
    Range,
    CustomLocation,
    Interface,
    IntermediateCertificate)
from python_kemptech_api.utils import (
    send_response,
    validate_port,
    validate_ip,
    validate_protocol,
    get_api_bool_string,
    cast_to_list,
    get_dict_entry_as_list,
    get_sub_vs_list_from_data,
    build_object,
    list_object
)

log = logging.getLogger(__name__)


class BaseKempAppliance(HttpClient, AccessInfoMixin):
    def __init__(self, ip, username=None, password=None, port=443, cert=None):
        self.ip_address = ip
        self.username = username
        self.password = password
        self.port = port
        self.cert = cert
        self.access_point = "access"
        self.version = None

        super(BaseKempAppliance, self).__init__(utils.DEFAULT_TLS_VERSION,
                                                self.cert,
                                                user=self.username,
                                                password=self.password)

    def __repr__(self):
        return '{}:{}'.format(self.ip_address, self.port)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.version == other.version
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __gt__(self, other):
        if isinstance(other, self.__class__):
            return self.version > other.version
        else:
            return False

    def __lt__(self, other):
        if isinstance(other, self.__class__):
            return self.version < other.version
        else:
            return False

    def __ge__(self, other):
        if isinstance(other, self.__class__):
            return self.version >= other.version
        else:
            return False

    def __le__(self, other):
        if isinstance(other, self.__class__):
            return self.version <= other.version
        else:
            return False

    def _do_request_no_api(self, cmd):
        """Perform a get in the context of enabling the API."""
        url = "https://{}:{}/{}".format(self.ip_address, self.port, cmd)
        if self.cert:
            resp = self._tls_session.get(url, verify=False, timeout=1, cert=self.cert)
        else:
            resp = self._tls_session.get(url, verify=False, timeout=1,
                                         auth=(self.username, self.password))
            self._tls_session.close()
        return resp.status_code

    @property
    def endpoint(self):
        return "https://{}:{}/{}".format(self.ip_address, self.port, self.access_point)

    @property
    def capabilities(self):
        if self.version is None:
            self.version = "7.1.34"
        return CAPABILITIES.get(self.version, CAPABILITIES[DEFAULT])

    def _get_curl_command_list(self, command):
        """
        Return a properly formatted curl command equivalent of the API call
        :param command:
        :return:
        """
        curl = ['curl', '-s', '-k', '--connect-timeout', str(utils.TIMEOUT)]
        command = '{}/{}'.format(self.endpoint, command)
        if self.cert:
            curl.extend(['-E', self.cert])
        else:
            curl.extend(['-u', '{}:{}'.format(self.username, self.password)])
        curl.append(command)
        return curl

    @property
    def license(self):
        """Current license on the LoadMaster

        :return: License information
        """
        response = self._get("/licenseinfo")

        if is_successful(response):
            data = get_data(response)
            license_info = {}

            # Fix annoying API weirdness
            for k, v in data.items():
                k = k.lower()

                try:
                    if v[0] == '"':
                        v = v[1:]

                    if v[-1] == '"':
                        v = v[:-1]

                    if v[-1] == "\n":
                        v = v[:-1]
                except (IndexError, KeyError):
                    # Catch scenarios where there is no data
                    pass

                if isinstance(v, str):
                    v = v.replace("  ", " ")

                license_info[k] = v
        else:
            raise KempTechApiException(get_error_msg(response))

        return license_info

    @property
    def interfaces(self):
        """ Dictionary of named interfaces

        :return: Dict with interface name and Interface instance key / value pairs.
        """
        return {interface.interface: interface
                for interface in self.get_interfaces()}

    def __getitem__(self, parameter):
        return self.get_parameter(parameter)

    def __setitem__(self, parameter, value):
        self.set_parameter(parameter, value)

    def set_parameter(self, parameter, value):
        """Assign the value to the given loadmaster parameter

        :param parameter: A valid LoadMaster parameter.
        :type parameter: str.
        :param value: The value to be assigned
        :type value: str.
        :raises: LoadMasterParameterError
        """
        parameters = {
            'param': parameter,
            'value': value,
        }

        response = self._get('/set', parameters)

        if not is_successful(response):
            raise LoadMasterParameterError(self, parameters)

    @property
    def acl(self):
        return self.get_global_acl()

    def get_global_acl(self):
        return GlobalACL(self.access_info)

    def get_parameter(self, parameter):
        """Get the value of the given LoadMaster parameter

        :param parameter: A valid LoadMaster parameter.
        :type parameter: str.
        :return: str -- The parameter value
        """
        parameters = {
            'param': parameter,
        }
        response = self._get('/get', parameters)
        value = get_data_field(response, parameter)

        if isinstance(value, dict):
            # This hack converts possible HTML to an awful one string
            # disaster instead of returning parsed html as an OrderedDict.
            value = "".join("{!s}={!r}".format(key, val) for (key, val) in
                            sorted(value.items()))

        if parameter == "version":
            self.version = ".".join(value.split(".")[:3])

        return value

    def get_all_parameters(self):
        """ Return all parameters as a dict with lowercase keys
        :return: A dict of all the parameters, with the keys in lowercase
        """
        response = self._get("/getall")
        data = get_data(response)
        return dict((k.lower(), v) for k, v in data.items())

    def enable_api(self, health_check_api=False):
        """ Enable LoadMaster RESTfull API

        This method will attempt to enable the LoadMaster's REST API the 'right' way
        by initially trying to set it with enableapi parameter. If this fails it will
        attempt to set it the old way using the progs URL.

        :param health_check_api: If True, an extra call to the API will be made
                                 to verify operability, only works for machines older
                                 than 7.2.36.
        :return: True if successfully enabled.
        """
        # Can't use the HttpClient methods for this as the endpoint is different
        # (or has strict stipulations) when attempting to enable the API.
        try:
            status_code = self._do_request_no_api('access/set?param=enableapi&value=yes')
            if status_code == 404:
                self._do_request_no_api('progs/doconfig/enableapi/set/yes')
                status_code = self._do_request_no_api('progs/status/logout')
                if status_code != 200:
                    raise KempTechApiException(code=status_code)
                if health_check_api:
                    # Health check to see if API was actually enabled
                    # if it failed its usually due to auth error so raise a 401
                    status_code = self._do_request_no_api('access/get?param=version')
                    if status_code != 200:
                        raise KempTechApiException(code=401)
            elif status_code != 200:
                raise KempTechApiException(code=status_code)
            return True
        except exceptions.RequestException as e:
            raise KempTechApiException(msg="Enable API failed because of: {}".format(
                e.__class__.__name__), is_xml_msg=False)

    def stats(self):
        response = self._get('/stats')
        return send_response(response)

    def update_firmware(self, file):
        response = self._post('/installpatch', file)
        self.version = None
        return is_successful(response)

    def restore_firmware(self):
        response = self._get("/restorepatch")
        self.version = None
        return is_successful(response)

    def reset_logs(self):
        response = self._get("/logging/resetlogs")
        return is_successful(response)

    def download_logs(self, filename=None):
        response = self._get("/logging/downloadlogs")

        filename = filename or "LoadMaster_" + self.ip_address + "_Logs.tgz"

        with open(filename, 'w') as f:
            f.write(response)

        return filename

    def change_bal_password(self, new_password):
        parameters = {
            "currpassword": self.password,
            "password": new_password
        }

        response = self._get("/usersetsyspassword", parameters=parameters)

        if is_successful(response):
            self.password = new_password
            return True
        else:
            return False

    def add_local_user(self, user, password=None, radius=False):
        params = {
            'user': user,
            'radius': get_api_bool_string(radius),
        }
        if password is None:
            params['nopass'] = 'y'
        else:
            params['password'] = password

        try:
            response = self._get('/useraddlocal', params)
        except KempTechApiException as e:
            if str(e) == "User already exists.":
                raise UserAlreadyExistsException(user, self.ip_address)
            else:
                raise
        return send_response(response)

    def delete_local_user(self, user):
        params = {'user': user}
        response = self._get('/userdellocal', params)
        return send_response(response)

    def set_user_perms(self, user, perms=None):
        perms = [] if perms is None else perms
        perms = cast_to_list(perms)
        params = {
            'user': user,
            'perms': ",".join([perm for perm in perms]),
        }
        response = self._get('/usersetperms', params)
        return send_response(response)

    def new_user_cert(self, user):
        params = {'user': user}
        response = self._get('/usernewcert', params)
        return send_response(response)

    def download_user_cert(self, user, location=os.curdir):
        file_name = os.path.join(location, "{}.cert".format(user))

        with open(file_name, 'wb') as file:
            cmd = self._get_curl_command_list('userdownloadcert?user={}'
                                              .format(user))
            subprocess.call(cmd, stdout=file)
            file.seek(0, 2)
            if file.tell() == 0:
                raise DownloadUserCertFailed(self.ip_address)
        return file_name

    def shutdown(self):
        response = self._get('/shutdown')
        return is_successful(response)

    def reboot(self):
        response = self._get('/reboot')
        return is_successful(response)

    def get_license_info(self):
        try:
            response = self._get('360/licenseinfo')
            return send_response(response)

        except KempTechApiException:
            raise CommandNotAvailableException(
                self, '/access360/licenseinfo')

    def list_addons(self):
        response = self._get('/listaddon')
        return send_response(response)

    def get_diagnostic(self, diagnostic):
        response = self._get('/logging/{}'.format(diagnostic))
        return response

    def backup(self, location='backups'):
        if not os.path.exists(location):
            os.makedirs(location)
        file_name = os.path.join(location, "{}_{}.backup".format(
            self.ip_address, time.strftime("%Y-%m-%d_%H:%M:%S")))

        with open(file_name, 'wb') as file:
            cmd = self._get_curl_command_list('backup')
            subprocess.call(cmd, stdout=file)
            file.seek(0, 2)
            if file.tell() == 0:
                raise BackupFailed(self.ip_address)
        return file_name

    def restore_backup(self, backup_type, file):
        # 1 LoadMaster Base Configuration
        # 2 Virtual Service Configuration
        # 3 GEO Configuration
        if backup_type not in [1, 2, 3]:
            backup_type = 2
        params = {"type": backup_type}
        response = self._post('/restore', file=file,
                              parameters=params)
        return send_response(response)

    def alsi_license(self, kemp_id, password):
        params = {
            "kempid": kemp_id,
            "password": password,
        }
        response = self._get('/alsilicense', parameters=params)
        return send_response(response)

    def offline_license(self, license_file):
        response = self._post("/license", file=license_file)
        return send_response(response)

    def set_initial_password(self, password):
        params = {"passwd": password}
        response = self._get('/set_initial_passwd', parameters=params)
        return send_response(response)

    def kill_asl_instance(self):
        response = self._get('/killaslinstance')
        return send_response(response)

    def get_interfaces(self):
        interfaces = []
        try:
            response = self._get('/showiface')
            data = get_data(response)
            interfaces_data = data.get('Interface', [])
            interfaces_data = cast_to_list(interfaces_data)
            for iface_data in interfaces_data:
                iface = build_object(Interface, self.access_info, iface_data)
                # Check for duplicate IPs as there is a bug in LoadMaster showiface
                # that makes unset interfaces inherit the previous interfaces IP.
                for interface in interfaces:
                    if iface.addr == interface.addr:
                        break
                else:
                    interfaces.append(iface)
            return interfaces
        except KempTechApiException as e:
            # If showiface does not support listing of all interfaces (possibly due to
            # older version loadmasters) do it the hard way by doing it one by one getting
            # the IDs from /access/stats.
            # This will cause N+1 API calls to occur, N being the number of interfaces.
            if hasattr(e, "status_code") and e.status_code == 422:
                try:
                    response = self._get('/stats')
                    data = get_data(response)
                    xml_object = data.get('Network', {})
                except KempTechApiException:
                    xml_object = {}

                for k, v in xml_object.items():
                    obj = self.get_interface(v['ifaceID'])
                    obj.name = k
                    interfaces.append(obj)
                return interfaces
            else:
                raise

    def get_interface(self, interface):
        response = self._get("/showiface", {"interface": interface})
        xml_object = get_data(response)
        obj = build_object(Interface, self.access_info, xml_object)
        return obj

    def initial_license(self,
                        license_type=None,
                        callhome=None,
                        new_password=None,
                        kempid=None):

        self.get_eula()
        self.accept_eula(license_type)
        self.set_callhome(callhome)

        if kempid is not None:
            self.alsi_license(kempid['username'], kempid['password'])
            self.initial_password(new_password)
        else:
            raise KempTechApiException("Please license before proceeding.")

    def get_eula(self):
        api = "/readeula"

        response = self._get(api)

        if is_successful(response):
            data = get_data(response)
        else:
            raise KempTechApiException(get_error_msg(response))

        self.magic = data['Magic']
        return data['Eula']

    def accept_eula(self, license_type="trial"):
        api = "/accepteula"

        parameters = {
            "type": license_type,
            "magic": self.magic
        }

        response = self._get(api, parameters=parameters)

        if is_successful(response):
            data = get_data(response)
        else:
            raise KempTechApiException(get_error_msg(response))

        self.magic = data['Magic']

    def set_callhome(self, enabled=True):
        api = "/accepteula2"

        if enabled is True:
            enabled = "yes"
        else:
            enabled = "no"

        parameters = {
            "accept": enabled,
            "magic": self.magic
        }

        response = self._get(api, parameters=parameters)

        if not is_successful(response):
            raise KempTechApiException(get_error_msg(response))

    def initial_password(self, password="2fourall"):
        api = "/set_initial_passwd"

        parameters = {
            "passwd": password
        }

        response = self._get(api, parameters=parameters)

        if not is_successful(response):
            raise KempTechApiException(get_error_msg(response))

        self.password = password

    def ping(self, host, interface=None):
        parameters = {
            "addr": host
        }

        if interface is not None:
            parameters['intf'] = interface

        try:
            response = self._get("/logging/ping", parameters=parameters)
        except KempTechApiException:
            return False
        else:
            if "connect: Network is unreachable" in response:
                return False
            return True

    def refresh_dns(self):
        api = "/resolvenow"
        response = self._get(api)

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))


class Geo(BaseKempAppliance):
    """GEO API object."""
    _GEO_PARAMS = [
        "sourceofauthority",
        "namesrv",
        "soaemail",
        "ttl",
        "persist",
        "checkinterval",
        "conntimeout",
        "retryattempts"
    ]

    def __getitem__(self, parameter):
        if parameter.lower() in Geo._GEO_PARAMS:
            return self.get_geo_parameter(parameter)
        else:
            return self.get_parameter(parameter)

    def __setitem__(self, parameter, value):
        if parameter.lower() in Geo._GEO_PARAMS:
            self.set_geo_parameter(parameter, value)
        else:
            self.set_parameter(parameter, value)

    def set_geo_parameter(self, parameter, value):
        """assign the value to the given loadmaster parameter

        :param parameter: a valid LoadMaster parameter.
        :type parameter: str.
        :param value: the value to be assigned
        :type value: str.
        :raises: LoadMasterParameterError
        """
        parameters = {
            parameter: value
        }
        response = self._get('/modparams', parameters)
        if not is_successful(response):
            raise LoadMasterParameterError(self, parameters)

    def get_geo_parameter(self, parameter):
        """get the value of the given GEO parameter

        :param parameter: a valid GEO parameter.
        :type parameter: str.
        :return: str -- the parameter value
        """

        def _find_key_recursive(d, key):
            match = [k for k, v in d.items() if k.lower() == key.lower()]
            if match:
                return d[match.pop()]
            for v in d.values():
                if isinstance(v, dict):
                    item = _find_key_recursive(v, key)
                    if item is not None:
                        return item

        response = self._get('/listparams')
        data = get_data(response)
        value = _find_key_recursive(data, parameter)
        return value

    def enable_geo(self):
        response = self._get('/enablegeo')
        return is_successful(response)

    def disable_geo(self):
        response = self._get('/disablegeo')
        return is_successful(response)

    @property
    def fqdns(self):
        return {fqdn.fqdn: fqdn for fqdn in self.get_fqdns()}

    @property
    def clusters(self):
        return {cluster.ip: cluster for cluster in self.get_clusters()}

    @property
    def ipranges(self):
        return {iprange.ip: iprange for iprange in self.get_ranges()}

    @property
    def customlocations(self):
        return {customlocation.name: customlocation
                for customlocation in self.get_customlocations()}

    def get_acl_settings(self):
        response = self._get("/geoacl/getsettings")

        if is_successful(response):
            data = get_data(response)
            data = data['GeoAcl']
        else:
            raise KempTechApiException(get_error_msg(response))

        acl_settings = {}

        for k, v in data.items():
            if v == "yes":
                v = True
            elif v == "no":
                v = False
            elif v == "Never":
                v = None
            else:
                try:
                    v = int(v)  # pylint: disable=redefined-variable-type
                except ValueError:
                    pass

            acl_settings[k.lower()] = v

        return acl_settings

    def set_acl_settings(self,
                         autoupdate=None,
                         autoinstall=None,
                         installtime=None):
        if autoupdate is not None:
            command = "setautoupdate"
            key = "enable"
            value = autoupdate

        elif autoinstall is not None:
            command = "setautoinstall"
            key = "enable"
            value = autoinstall

        elif installtime is not None:
            command = "setinstalltime"
            key = "hour"
            value = autoinstall

        if value in [True, "yes", "y", "1"]:
            value = "yes"

        if value in [False, "no", "n", "0"]:
            value = "no"

        parameters = {
            key: value
        }

        response = self._get("/geoacl/{}".format(command), parameters)

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

    @property
    def acl_autoupdate(self):
        return self.get_acl_settings()['autoupdate']

    @acl_autoupdate.setter
    def acl_autoupdate(self, value):
        self.set_acl_settings(autoupdate=value)

    @property
    def acl_autoinstall(self):
        return self.get_acl_settings()['autoinstall']

    @acl_autoinstall.setter
    def acl_autoinstall(self, value):
        self.set_acl_settings(autoinstall=value)

    @property
    def acl_installtime(self):
        return self.get_acl_settings()['installtime']

    @acl_installtime.setter
    def acl_installtime(self, value):
        self.set_acl_settings(installtime=value)

    @property
    def acl_lastupdated(self):
        return self.get_acl_settings()['lastupdated']

    @property
    def acl_lastinstalled(self):
        return self.get_acl_settings()['lastinstalled']

    def acl_update(self):
        response = self._get("/geoacl/updatenow")

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

    def acl_install(self):
        response = self._get("/geoacl/installnow")

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

    @property
    def acl_download(self):
        response = self._get("/geoacl/downloadlist")

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

        return response

    @property
    def acl_changes(self):
        response = self._get("/geoacl/downloadchanges")

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

        return response

    def get_acl(self, type):
        parameters = {
            "type": type
        }
        response = self._get("/geoacl/listcustom", parameters)

        if is_successful(response):
            data = get_data(response)
        else:
            raise KempTechApiException(get_error_msg(response))

        list_tag = "{}list".format(type).capitalize()

        acl_list = data[list_tag]

        if acl_list is None:
            acl_list = []
        elif isinstance(acl_list, dict):
            acl_list = acl_list.get('addr')

        if not isinstance(acl_list, list):
            acl_list = [acl_list]

        return acl_list

    def add_acl(self, type, value):
        parameters = {
            "type": type,
            "addr": value
        }

        response = self._get("/geoacl/addcustom", parameters)

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

    def remove_acl(self, type, value):
        parameters = {
            "type": type,
            "addr": value
        }

        response = self._get("/geoacl/removecustom", parameters)

        if is_successful(response):
            pass
        else:
            raise KempTechApiException(get_error_msg(response))

    def set_acl(self, type, value):
        if not isinstance(value, list):
            raise ValueError("Setting ACL expects a list of IP networks")

        current = self.get_acl(type)

        to_delete = list(set(current) - set(value))
        to_add = list(set(value) - set(current))

        for address in to_delete:
            self.remove_acl(type, address)

        for address in to_add:
            self.add_acl(type, address)

    @property
    def acl_whitelist(self):
        return self.get_acl("white")

    @acl_whitelist.setter
    def acl_whitelist(self, value):
        self.set_acl("white", value)

    @property
    def acl_blacklist(self):
        return self.get_acl("black")

    @acl_blacklist.setter
    def acl_blacklist(self, value):
        self.set_acl("black", value)

    def create_fqdn(self, fqdn):
        return Fqdn(self.access_info, fqdn)

    def get_fqdns(self):
        try:
            response = self._get("/listfqdns")
            data = get_data(response)
            return list_object(Fqdn, self.access_info, data)
        except KempTechApiException:
            # If API returns 'No geo data found' return an empty list
            return []

    def get_fqdn(self, fqdn):
        service_id = {
            "fqdn": fqdn
        }

        # Append a . to the fqdn if it does not
        # exist as it is required for FQDN syntax
        if service_id['fqdn'][-1] != ".":
            service_id['fqdn'] += "."

        response = self._get("/showfqdn", service_id)
        data = get_data(response)
        fqdn = build_object(Fqdn, self.access_info, data)
        return fqdn

    def create_cluster(self, ip, name):
        """Cluster factory with pre-configured LoadMaster connection."""
        return Cluster(self.access_info, ip, name)

    def get_clusters(self):
        try:
            response = self._get("/listclusters")
            data = get_data(response)
            clusters = data.get('cluster', [])
        except KempTechApiException:
            clusters = []

        cluster_list = []
        clusters = cast_to_list(clusters)
        for c in clusters:
            cluster = self.build_cluster(c)
            cluster_list.append(cluster)
        return cluster_list

    def get_cluster(self, ip):
        service_id = {"ip": ip}
        response = self._get("/showcluster", service_id)
        data = get_data(response)
        cluster_data = data.get('cluster')
        # again line below will fail with ValidationError if empty response
        if not isinstance(cluster_data, dict):
            raise LoadMasterParameterError(
                "Unexepected number of clusters returned",
                cluster_data)
        cluster = self.build_cluster(cluster_data)
        return cluster

    def build_cluster(self, cluster):
        """Create a Cluster instance with standard defaults"""
        cluster_object = Cluster(self.access_info,
                                 cluster.get('IPAddress'),
                                 cluster.get('Name'))
        cluster_object.populate_default_attributes(cluster)
        return cluster_object

    def create_range(self, ip, mask):
        """Range factory with pre-configured LoadMaster connection."""
        iprange = Range(self.access_info, ip, mask)
        return iprange

    def get_ranges(self):
        try:
            response = self._get("/listips")
            data = get_data(response)
            ranges = data.get('IPAddress', [])
        except KempTechApiException:
            ranges = []

        range_list = []
        ranges = cast_to_list(ranges)
        for r in ranges:
            range = self.build_range(r)
            range_list.append(range)
        return range_list

    def get_range(self, ip):
        service_id = {"ipaddress": ip}
        response = self._get("/showip", service_id)
        data = get_data(response)
        # again line below will fail with ValidationError if empty response
        range_data = data.get('cluster', {})
        if not isinstance(range_data, dict):
            raise LoadMasterParameterError(
                "Unexepected number of ranges returned", range_data)
        return self.build_range(range_data)

    def build_range(self, range):
        """Create a Range instance with standard defaults"""
        range_object = Range(self.access_info,
                             range.get('IPAddress'),
                             range.get('Mask'))
        range_object.populate_default_attributes(range)
        return range_object

    def create_customlocation(self, name):
        """CustomLocation factory with pre-configured LoadMaster connection."""
        return CustomLocation(self.access_info, name)

    def get_customlocations(self):
        try:
            response = self._get("/listcustomlocation")
            data = get_data(response)
            customlocations = data.get('location', [])
        except KempTechApiException:
            customlocations = []

        customlocation_list = []
        customlocations = cast_to_list(customlocations)
        for c in customlocations:
            customlocation = self.build_customlocation(c)
            customlocation_list.append(customlocation)
        return customlocation_list

    def get_customlocation(self, name):
        service_id = {"name": name}
        response = self._get("/listcustomlocation", service_id)
        data = get_data(response)
        # again line below will fail with ValidationError if empty response
        customlocations_data = data.get('location', {})

        customlocation_data = [x for x in customlocations_data
                               if x['Name'] == name]

        if not isinstance(customlocation_data, dict):
            raise LoadMasterParameterError(
                "Unexepected number of custom locations returned",
                customlocation_data)
        customlocation = self.build_range(customlocation_data)
        return customlocation

    def build_customlocation(self, customlocation):
        """Create a Range instance with standard defaults"""
        customlocation_object = CustomLocation(
            self.access_info,
            customlocation.get('Name'))
        return customlocation_object


class LoadMaster(BaseKempAppliance):
    """LoadMaster API object."""

    @property
    def vs(self):
        return {int(vs.index): vs for vs in self.get_virtual_services()}

    @property
    def rules(self):
        return {rule.name: rule for rule in self.get_rules()}

    @property
    def sso(self):
        return {sso.name: sso for sso in self.get_ssos()}

    @property
    def templates(self):
        return {template.name: template for template in self.get_templates()}

    @property
    def certificates(self):
        return {certificate.certname: certificate for certificate in
                self.get_certificates()}

    def get_adaptive_parameters(self):
        response = self._get("/showadaptive")
        data = get_data(response)

        return data['Data']

    def set_adaptive_parameters(self,
                                adaptiveurl=None,
                                adaptiveport=None,
                                adaptiveinterval=None,
                                minpercent=None):
        parameters = {}

        if adaptiveurl is not None:
            parameters['AdaptiveURL'] = adaptiveurl
        if adaptiveport is not None:
            validate_port(adaptiveport)
            parameters['AdaptivePort'] = adaptiveport
        if adaptiveinterval is not None:
            try:
                parameters['AdaptiveInterval'] = int(adaptiveinterval)
            except ValueError:
                raise LoadMasterParameterError(
                    "AdaptiveInterval specified is not an integer",
                    adaptiveinterval)
        if minpercent is not None:
            try:
                parameters['MinPercent'] = int(minpercent)
            except ValueError:
                raise LoadMasterParameterError(
                    "MinPercent specified is not an integer",
                    minpercent)

        response = self._get("/modadaptive", parameters)

        if not is_successful(response):
            raise LoadMasterParameterError(self, parameters)

    def get_check_parameters(self):
        response = self._get("/showhealth")
        data = get_data(response)
        formatted = {}

        for k, v in data.items():
            formatted[k.lower()] = int(v)

        return formatted

    def set_check_parameters(self,
                             retryinterval=None,
                             timeout=None,
                             retrycount=None):
        parameters = {}
        if timeout is not None:
            try:
                parameters['Timeout'] = int(timeout)
            except ValueError:
                raise LoadMasterParameterError(
                    "Timeout specified is not an integer",
                    timeout)
        if retrycount is not None:
            try:
                parameters['RetryCount'] = int(retrycount)
            except ValueError:
                raise LoadMasterParameterError(
                    "RetryCount specified is not an integer",
                    retrycount)
        if retryinterval is not None:
            try:
                parameters['RetryInterval'] = int(retryinterval)
            except ValueError:
                raise LoadMasterParameterError(
                    "RetryInterval specified is not an integer",
                    retryinterval)

        response = self._get("/modhealth", parameters)

        if not is_successful(response):
            raise LoadMasterParameterError(self, parameters)

    def create_sso(self, name):
        return Sso(self.access_info, name)

    def get_ssos(self):
        response = self._get("/showdomain")
        ssos = get_data(response).get("Domain") or []
        ssos_list = []

        # if there is no Rule key, build_virtual_services will fail with a
        # ValidationError, which is the best we can do for now
        # (without changing the upstream code and raising an exception earlier,
        # possibly retrying)
        if not isinstance(ssos, list):
            ssos = [ssos]
        for sso in ssos:
            sso_object = self.build_sso(sso)
            ssos_list.append(sso_object)
        return ssos_list

    def get_sso(self, name):
        service_id = {"name": name}
        response = self._get("/showdomain", service_id)
        sso = get_data(response).get("Domain")

        # again line below will fail with ValidationError if empty response
        sso_object = self.build_sso(sso)
        return sso_object

    def build_sso(self, sso):
        """Create a Rule instance with standard defaults"""
        sso_object = Sso(self.access_info, sso.get('Name'))

        sso_object.populate_default_attributes(sso)
        return sso_object

    def create_rule(self, name, pattern):
        return Rule(self.access_info, name, pattern)

    def get_rules(self):
        response = self._get("/showrule")
        data = get_data(response)
        rules_list = []

        for rule_type, rules in data.items():
            rules = cast_to_list(rules)
            for rule in rules:
                rule['type'] = rule_type
                rule_object = build_object(Rule, self.access_info, rule)
                rules_list.append(rule_object)

        return rules_list

    def get_rule(self, name):
        response = self._get("/showrule", {"name": name})
        data = get_data(response)
        rules_list = []
        rule_object = None

        if len(data) > 1:
            raise KempTechApiException("Too many rules returned")

        for rule_type, rules in data.items():
            rules = cast_to_list(rules)

            for rule in rules:
                rule['type'] = rule_type
                rule_object = build_object(Rule, self.access_info, rule)
                rules_list.append(rule_object)

        return rule_object

    def create_cipherset(self, cipherset_name, ciphers):
        cipherset = CipherSet(self.access_info, cipherset_name, ciphers)
        cipherset.save()

    def create_certificate(self, certificate, certfile, certpass=None):
        """Certificate factory with pre-configured LoadMaster connection."""
        cert = Certificate(self.access_info,
                           certificate,
                           certfile=certfile,
                           certpass=certpass)
        return cert

    def create_intermediate_certificate(self, certificate, certfile):
        """Certificate factory with pre-configured LoadMaster connection."""
        cert = IntermediateCertificate(self.access_info,
                                       certificate,
                                       certfile=certfile)
        return cert

    def get_certificates(self, type='cert'):
        response = self._get("/listcert")
        data = get_data(response)
        certificates = []
        certs = data.get('cert', [])
        if not isinstance(certs, list):
            certs = [certs]
        for cert in certs:
            certificate = self.build_certificate(cert)
            certificates.append(certificate)
        return certificates

    def get_intermediate_certificates(self, type='cert'):
        response = self._get("/listintermediate")
        data = get_data(response)
        certificates = []
        certs = data.get('cert', [])
        if not isinstance(certs, list):
            certs = [certs]
        for cert in certs:
            certificate = self.build_intermediate_certificate(cert)
            certificates.append(certificate)
        return certificates

    def build_certificate(self, certificate, certfile=None,
                          certpass=None):
        """Create a Certificte instance named certificate"""
        if certfile is not None:
            cert = Certificate(self.access_info, certificate,
                               certfile=certfile, certpass=certpass)
        else:
            cert = Certificate(self.access_info, certificate)
        return cert

    def build_intermediate_certificate(self, certificate, certfile=None):
        """Create a Certificte instance named certificate"""
        if certfile is not None:
            cert = IntermediateCertificate(self.access_info,
                                           certificate,
                                           certfile=certfile)
        else:
            cert = IntermediateCertificate(self.access_info, certificate)
        return cert

    def create_virtual_service(self, ip, port=80, protocol="tcp"):
        return VirtualService(self.access_info, ip, port, protocol)

    def get_virtual_services(self):
        response = self._get("/listvs")
        data = get_data(response)
        virtual_services = []
        services = data.get('VS', [])
        services = cast_to_list(services)
        for service in services:
            master_vs_id = int(service.get('MasterVSID', 0))
            if master_vs_id != 0:
                for vs in services:
                    if int(vs.get("Index", 0)) == master_vs_id:
                        virt_serv = self.build_virtual_service(service, vs)
            else:
                virt_serv = self.build_virtual_service(service, response)
            virtual_services.append(virt_serv)
        return virtual_services

    def get_virtual_service(self, index=None, address=None, port=None,
                            protocol=None):
        if index is None:
            validate_ip(address)
            validate_port(port)
            validate_protocol(protocol)
            service_id = {"vs": address, "port": port, "prot": protocol}
        else:
            service_id = {"vs": index}
        response = self._get("/showvs", service_id)
        service = get_data(response)
        # again line below will fail with ValidationError if empty response
        virt_serv = self.build_virtual_service(service)
        return virt_serv

    def build_virtual_service(self, service, response=None):
        """Create a VirtualService instance with populated with API parameters

        This does not include potentially attached real servers
        :param service: OrderedDict populated with virtual service data
        :param response: Optional response of a listvs call. This acts as a
        cache, if you want to create a lot of VirtualService
        objects in a row, such as with looping, you can call
        listvs and pass the response in each time and this
        will nullify the extra listvs calls.
        :return: VirtualService object with populated attributes
        """
        is_sub_vs = True if int(service.get('MasterVSID', 0)) != 0 else False
        if is_sub_vs:
            # `response` needs to be a dict in here
            # Add lb properties to the sub vs
            if response is None:
                response = self._get("/showvs",
                                     {"vs": service.get('MasterVSID')})
                parent_vs_data = get_data(response)
            else:
                parent_vs_data = response
            subvs_lb_props = get_sub_vs_list_from_data(parent_vs_data)[1]
            virt_serv = VirtualService(self.access_info, service.get('Index'),
                                       is_sub_vs=True)
            virt_serv.subvs_data = subvs_lb_props[service.get('Index')]
            virt_serv.subvs_data['parentvs'] = service.get('MasterVSID')
        else:
            # `response` needs to be a raw xml output here
            # Add any sub VSs to the top level VS
            if response is None:
                response = self._get("/listvs")
            data = get_data(response)
            virt_serv = VirtualService(self.access_info,
                                       service.get('VSAddress'),
                                       service.get('VSPort'),
                                       service.get('Protocol'),
                                       is_sub_vs=False)
            virt_serv.subvs_entries = []
            services = get_dict_entry_as_list("VS", data)
            this_vs_index = service.get('Index')
            for vs in services:
                # add subvs to parent vs
                if vs['MasterVSID'] == this_vs_index:
                    subvs = VirtualService(self.access_info, vs['Index'],
                                           is_sub_vs=True)
                    subvs.populate_default_attributes(vs)
                    subvs_api_entries = service.get("SubVS", [])
                    subvs_api_entries = cast_to_list(subvs_api_entries)
                    for subvs_api in subvs_api_entries:
                        # add the "Rs" part of the subvs to the subvs instance
                        if subvs_api["VSIndex"] == subvs.index:
                            subvs.subvs_data = subvs_api
                            # Have to add a parentvs hook to make life easy
                            subvs.subvs_data['parentvs'] = this_vs_index
                    virt_serv.subvs_entries.append(subvs)
        virt_serv.populate_default_attributes(service)
        return virt_serv

    def get_all_objects(self):
        # x variables are the object while x_data is the OrderedDict
        virtual_services = []
        response = self._get("/listvs")
        data = get_data(response)
        virtual_services_data = data.get('VS', [])
        virtual_services_data = cast_to_list(virtual_services_data)

        # create vs and rs objects at this point
        # loop through all vss and attach matching real server objects
        for service_data in virtual_services_data:
            master_vs_id = int(service_data.get('MasterVSID', 0))
            if master_vs_id != 0:
                for vs in virtual_services_data:
                    if int(vs.get("Index", 0)) == master_vs_id:
                        virt_serv = self.build_virtual_service(service_data,
                                                               vs)
            else:
                virt_serv = self.build_virtual_service(service_data, response)
            real_servers = cast_to_list(service_data.get("Rs", []))
            for server_data in real_servers:
                rs = virt_serv.build_real_server(server_data)
                virt_serv.real_servers.append(rs)
            virtual_services.append(virt_serv)
        # replace subvs's with vs's that have RSs in them.
        for vs in virtual_services:
            for subvs in vs.subvs_entries:
                for top_level_vs in virtual_services:
                    if subvs.index == top_level_vs.index:
                        subvs.real_servers = top_level_vs.real_servers

        return virtual_services

    def clone_virtual_service(self, service, ip=None, port=None, protocol=None,
                              enable=True,
                              dry_run=False):
        """Given a VirtualService instance, add it to this LoadMaster

        :param service: The VirtualService instance to clone
        :param ip: The new IP address of the virtual service
        :param port: The new port of the virtual service
        :param protocol: The new protocol of the virtual service
        :param enable: Enable the VirtualService
        :param dry_run: Don't save the VirtualSerivce immediately
        :return: The altered VirtualService tied to the this LoadMaster
        """
        if not isinstance(service, VirtualService):
            raise NotVirtualServiceInstanceError()

        service.endpoint = self.endpoint
        service.ip_address = self.ip_address
        service.cert = self.cert

        service.index = None
        service.vs = ip or service.vs
        service.port = port or service.port
        service.prot = protocol or service.prot

        service.enable = get_api_bool_string(enable)

        if not dry_run:
            service.save()

        return service

    def upload_template(self, file):
        # Deprecated, use create_template
        response = self._post('/uploadtemplate', file)
        return send_response(response)

    def create_template(self, file):
        existing = self.templates.keys()

        self._post("/uploadtemplate", file)

        uploaded_templates = {k: v for k, v in self.templates.items()
                              if k not in existing}

        return uploaded_templates

    def get_templates(self):
        response = self._get("/listtemplates")
        data = get_data(response)
        return list_object(Template, self.access_info, data)

    def get_template(self, name):
        # There is not 'get' for templates, only list.
        templates = self.get_templates()
        for template in templates:
            if template.name == name:
                return template

    def list_templates(self):
        # Backward compatability
        return self.get_templates()

    def delete_template(self, template_name):
        params = {'name': template_name}
        response = self._get('/deltemplate', parameters=params)
        return send_response(response)

    def apply_template(self, virtual_ip, port, protocol, template_name,
                       nickname=None):
        params = {
            'vs': virtual_ip,
            'port': port,
            'prot': protocol,
            'name': template_name,
        }

        existing = self.vs.keys()

        if nickname is not None:
            params['nickname'] = nickname

        response = self._get("/addvs", parameters=params)

        if is_successful(response):
            vs = {k: v for k, v in self.vs.items()
                  if k not in existing}
        else:
            raise KempTechApiException(get_error_msg(response))

        return vs

    def get_sdn_controller(self):
        response = self._get('/getsdncontroller')
        return send_response(response)

    def get_sdn_info(self):
        response = self._get('/sdninfo')
        return send_response(response)


class LoadMasterGeo(LoadMaster, Geo):
    pass
