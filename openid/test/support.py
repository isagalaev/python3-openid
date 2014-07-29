import urllib.request
import urllib.error
import urllib.parse
import io
import re
import os
from logging.handlers import BufferingHandler
import logging

from openid import message


DATAPATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


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
        return self.headers

    def read(self, *args):
        return self._body.read(*args)

    def getheader(self, name):
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower())


def gentests(cls):
    '''
    TestCase class decorator for data-driven tests.

    Reads a list of (name, args) pairs from cls.data and generates a separate
    test method named 'test_<name>' for each pair. The test method would call
    the method '_test' defined in a class to perform actual testing, passing it
    the args.
    '''
    for name, args in cls.data:
        def g(*args):
            def test_method(self):
                self._test(*args)
            return test_method
        method = g(*args)
        method.__name__ = 'test_' + name
        setattr(cls, method.__name__, method)
    return cls


def urlopen(request, data=None):
    if isinstance(request, str):
        request = urllib.request.Request(request)
    # track the last call arguments
    urlopen.request = request
    urlopen.data = data

    url = request.get_full_url()
    parts = urllib.parse.urlparse(url)
    if parts.netloc.split(':')[0] not in ['unittest', 'proxy.xri.net']:
        raise urllib.error.URLError('Wrong host: %s' % parts.netloc)
    path = parts.path.lstrip('/')
    if path.isdigit():
        status = int(path)
        if 300 <= status < 400:
            raise urllib.error.HTTPError(url, 400, 'Can\'t return 3xx status', {}, io.BytesIO())
        if 400 <= status:
            raise urllib.error.HTTPError(url, status, 'Requested status: %s' % status, {}, io.BytesIO())
        body = b'OK'
    else:
        try:
            status = 200
            if parts.netloc == 'proxy.xri.net':
                path = path.replace('=', '_').replace('*', '_') + '.xri'
            with open(os.path.join(DATAPATH, path), 'rb') as f:
                body = f.read()
        except FileNotFoundError:
            raise urllib.error.HTTPError(url, 404, '%s not found' % path, {}, io.BytesIO())

    headers = {
        'Server': 'Urlopen-Mock',
        'Date': 'Mon, 21 Jul 2014 19:52:42 GMT',
        'Content-type': 'text/plain',
        'Content-length': len(body),
    }
    query = urllib.parse.parse_qs(parts.query)
    extra_headers = query.get('header', [])
    headers.update(h.split(': ', 1) for h in extra_headers)
    return HTTPResponse(url, status, headers, body)
