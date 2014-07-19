from openid import message
import io
from logging.handlers import BufferingHandler
import logging

class TestHandler(BufferingHandler):
    def __init__(self, messages):
        BufferingHandler.__init__(self, 0)
        self.messages = messages

    def shouldFlush(self):
        return False

    def emit(self, record):
        self.messages.append(record.__dict__)

class OpenIDTestMixin(object):
    def failUnlessOpenIDValueEquals(self, msg, key, expected, ns=None):
        if ns is None:
            ns = message.OPENID_NS

        actual = msg.getArg(ns, key)
        error_format = 'Wrong value for openid.%s: expected=%s, actual=%s'
        error_message = error_format % (key, expected, actual)
        self.assertEqual(expected, actual, error_message)

    def failIfOpenIDKeyExists(self, msg, key, ns=None):
        if ns is None:
            ns = message.OPENID_NS

        actual = msg.getArg(ns, key)
        error_message = 'openid.%s unexpectedly present: %s' % (key, actual)
        self.assertFalse(actual is not None, error_message)

class CatchLogs(object):
    def setUp(self):
        self.messages = []
        root_logger = logging.getLogger()
        self.old_log_level = root_logger.getEffectiveLevel()
        root_logger.setLevel(logging.DEBUG)

        self.handler = TestHandler(self.messages)
        formatter = logging.Formatter("%(message)s [%(asctime)s - %(name)s - %(levelname)s]")
        self.handler.setFormatter(formatter)
        root_logger.addHandler(self.handler)

    def tearDown(self):
        root_logger = logging.getLogger()
        root_logger.removeHandler(self.handler)
        root_logger.setLevel(self.old_log_level)

    def failUnlessLogMatches(self, *prefixes):
        """
        Check that the log messages contained in self.messages have
        prefixes in *prefixes.  Raise AssertionError if not, or if the
        number of prefixes is different than the number of log
        messages.
        """
        messages = [r['msg'] for r in self.messages]
        assert len(prefixes) == len(messages), \
               "Expected log prefixes %r, got %r" % (prefixes,
                                                     messages)

        for prefix, message in zip(prefixes, messages):
            assert message.startswith(prefix), \
                   "Expected log prefixes %r, got %r" % (prefixes,
                                                         messages)

    def failUnlessLogEmpty(self):
        self.failUnlessLogMatches()


class HTTPResponse:
    def __init__(self, url, status, headers=None, body=None):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self._body = io.BytesIO(body)

    def info():
        return self._headers

    def read(self, *args):
        return self._body.read(*args)

    def getheader(self, name):
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower())


def gentests(data):
    '''
    TestCase class decorator for data-driven tests.

    Given a list of (name, args) pairs the decorator generates a separate test
    method named 'test_<name>' for each pair. The test method would call the
    method '_test' defined in a class to perform actual testing, passing it
    the args.
    '''
    def decorator(cls):
        for name, args in data:
            def g(*args):
                def test_method(self):
                    self._test(*args)
                return test_method
            method = g(*args)
            method.__name__ = 'test_' + name
            setattr(cls, method.__name__, method)
        return cls
    return decorator
