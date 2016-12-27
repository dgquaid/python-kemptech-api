import inspect
from nose.tools import assert_equal, assert_raises, assert_is_none

# handle py3 and py2 cases:
try:
    import unittest.mock as mock
except ImportError:
    import mock

patch = mock.patch
sentinel = mock.sentinel

import python_kemptech_api.exceptions as exceptions
from python_kemptech_api.utils import IS_PY3

class Test_get_api_exception_message:

    def setup(self):
        self.p_get_error_msg = patch.object(exceptions, 'get_error_msg')
        self.get_error_msg = self.p_get_error_msg.start()

    def teardown(self):
        self.p_get_error_msg.stop()

    def test_msg_str_is_xml_msg(self):
        self.get_error_msg.return_value = sentinel.err
        res = exceptions.get_api_exception_message('a message', 401, True)
        assert_equal(res, sentinel.err)

    def test_msg_str_not_xml_msg(self):
        res = exceptions.get_api_exception_message('a message', 401, False)
        assert_equal(res, 'a message')

    def test_msg_None_status_code_ok(self):
        for is_xml_msg in (True, False):
            res = exceptions.get_api_exception_message(None, 401, is_xml_msg)
            assert_equal(res, '401 Client Error: Authorization required.')

    def test_msg_None_status_code_fail(self):
        for is_xml_msg in (True, False):
            res = exceptions.get_api_exception_message(None, 450, is_xml_msg)
            assert_equal(res, 'An unknown error has occurred (450).')


class Test_get_parameter_message:

    def test_dict_input(self):
        lm = 'my-loadmaster'
        parameters = {'param': 'a', 'value': 'b'}
        msg = exceptions.get_parameter_message(lm, parameters)
        assert_equal(msg,'my-loadmaster failed to set a: b')

    def test_non_dict_input(self):
        lm = 'my-loadmaster'
        parameters = 23  # Not a dictionary
        msg = exceptions.get_parameter_message(lm, parameters)
        if IS_PY3:
            assert_equal(msg,"my-loadmaster failed to set 23 ('int' object is not subscriptable)")
        else:
            assert_equal(msg,"my-loadmaster failed to set 23 ('int' object has no attribute '__getitem__')")


class Test_MissingInfo:

    def test_call(self):
        with assert_raises(exceptions.MissingInfo) as err:
            raise exceptions.MissingInfo('avalue')
        expect = "My service is missing the parameter_name parameter 'avalue'"
        assert_equal(str(err.exception), expect)


def test_status_code_is_set():
    expected = 45
    try:
        raise exceptions.UnauthorizedAccessError("1.1.1.1", code=expected)
    except exceptions.UnauthorizedAccessError as e:
        actual = e.status_code
        assert_equal(expected, actual)


def test_exception_inits():
    """Ensure that all the __init__s of exceptions defined in exceptions.py
    are constructed correctly (ie without syntax errors)
    """
    errors = []
    exception_classes = get_exception_classes_gen()

    for ex in exception_classes:

        try:
            check_exception_init(ex)
        except Exception as e:
            errors += ["{} failed with '{}'".format(ex, e)]

    if errors:
        for err in errors:
           print (err)
        assert False


def get_exception_classes_gen():
    """generator yielding the next exception class in exceptions.py"""

    for attr in dir(exceptions):
        e = getattr(exceptions, attr)
        """we are only interested in Exception subclasses which have __init__
        as a methos, not as a slot ( python2.7 builtins have this case"""

        if inspect.isclass(e) and issubclass(e, Exception) :
            if IS_PY3:
                yield e

            # in python2 case, we have to check that the __init__ is actually
            # a method , and not a slot wrapper
            elif inspect.ismethod(getattr(e, '__init__')):
                yield e


def check_exception_init(ex):
    # get the expected argument list
    args = inspect.getargspec(ex.__init__)[0]
    #remove "self from this list
    args = args[1:]
    try:
        # we raise the exception using the names of the arguments as values (for simplicity)
        # so this is, eg, raise DownloadUserCertFailed('ip_address', 'code')
        raise ex(*args)
    except ex:
        pass
    except:
        raise

# tests for the test functions:

def test_check_exception_init_ok():
    class OKException(Exception):
        def __init__(self, param):
            super(OKException, self).__init__()

    assert_is_none(check_exception_init(OKException))

def test_check_exception_init_fails_if_syntax_error():
    class SyntaxErrorException(Exception):
        def __init__(self, param):
            syntax_error = param + 7
            super(SyntaxErrorException, self).__init__()

    with assert_raises(TypeError):
        check_exception_init(SyntaxErrorException)
