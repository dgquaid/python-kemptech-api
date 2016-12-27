import json
from nose.tools import assert_equal, assert_in

import python_kemptech_api.client as client
import python_kemptech_api.generic


class Test_KempBaseObjectModel:

    def test_to_api_dict(self):
        loadmaster_access = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }

        kbo = python_kemptech_api.generic.BaseKempObject(loadmaster_access)
        kbo.ip_address = 'ip'
        kbo.interesting = 'very'
        kbo._ignore_me = 'lalala'

        res = kbo.to_api_dict()
        assert_equal(res, {"interesting": "very"})

    def test_repr(self):
        class MySubclass(python_kemptech_api.generic.BaseKempObject):
            pass

        loadmaster_access = {
            "endpoint": "https://1.1.1.1:443/access",
            "ip_address": "1.1.1.1",
            "auth": ("bal", "2fourall"),
        }

        my = MySubclass(loadmaster_access)
        my.stuff = 'x'

        assert_equal("MySubclass ", str(my)[:11])

        data = json.loads(str(my)[11:])
        assert_equal(data['endpoint'], 'https://1.1.1.1:443/access')
        assert_equal(data['stuff'], 'x')
        assert_equal(data['ip_address'], '1.1.1.1')
