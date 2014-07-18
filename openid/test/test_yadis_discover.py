#!/usr/bin/env python

"""Tests for yadis.discover.

@todo: Now that yadis.discover uses urljr.fetchers, we should be able to do
   tests with a mock fetcher instead of spawning threads with BaseHTTPServer.
"""

import unittest
import urllib.parse
import urllib.error
import re
import types
import io

from openid.yadis.discover import discover, DiscoveryFailure

from openid import fetchers

from . import discoverdata
from .support import HTTPResponse


STATUS_RE = re.compile(r'Status: (\d+) .*?$', re.MULTILINE)


def mkResponse(data):
    match = STATUS_RE.match(data)
    status = int(match.group(1))
    headers_str, body = data.split('\n\n', 1)
    headers = dict(l.split(': ') for l in headers_str.split('\n'))
    return HTTPResponse('<test>', status, headers=headers, body=body.encode('utf-8'))


class TestFetcher(object):
    def __init__(self, base_url):
        self.base_url = base_url

    def fetch(self, url, body=None, headers=None):
        current_url = url
        while True:
            parsed = urllib.parse.urlparse(current_url)
            path = parsed[2][1:]
            try:
                data = discoverdata.generateSample(path, self.base_url)
            except KeyError:
                data = '404 Not found\n\nNot found'

            response = mkResponse(data)
            if response.status >= 400:
                raise urllib.error.HTTPError(current_url, response.status, 'Test request failed', {}, io.BytesIO())
            if response.status in [301, 302, 303, 307]:
                current_url = response.getheader('location')
            else:
                response.url = current_url
                return response


class TestSecondGet(unittest.TestCase):
    class MockFetcher(object):
        def __init__(self):
            self.count = 0

        def fetch(self, uri, headers=None, body=None):
            self.count += 1
            if self.count == 1:
                headers = {
                    'X-XRDS-Location'.lower(): 'http://unittest/404',
                    }
                return HTTPResponse(uri, 200, headers, b'')
            else:
                raise urllib.error.HTTPError(uri, 404, 'Test request failed', {}, io.BytesIO(b''))

    def setUp(self):
        self._original = fetchers.fetch
        fetchers.fetch = self.MockFetcher().fetch

    def tearDown(self):
        fetchers.fetch = self._original

    def test_404(self):
        uri = "http://something.unittest/"
        self.assertRaises(urllib.error.HTTPError, discover, uri)


class _TestCase(unittest.TestCase):
    base_url = 'http://invalid.unittest/'

    def __init__(self, input_name, id_name, result_name, success):
        self.input_name = input_name
        self.id_name = id_name
        self.result_name = result_name
        self.success = success
        # Still not quite sure how to best construct these custom tests.
        # Between python2.3 and python2.4, a patch attached to pyunit.sf.net
        # bug #469444 got applied which breaks loadTestsFromModule on this
        # class if it has test_ or runTest methods.  So, kludge to change
        # the method name.
        unittest.TestCase.__init__(self, methodName='runCustomTest')

    def setUp(self):
        self._original = fetchers.fetch
        fetchers.fetch = TestFetcher(self.base_url).fetch

        self.input_url, self.expected = discoverdata.generateResult(
            self.base_url,
            self.input_name,
            self.id_name,
            self.result_name,
            self.success)

    def tearDown(self):
        fetchers.fetch = self._original

    def runCustomTest(self):
        if self.expected is urllib.error.HTTPError:
            self.assertRaises(urllib.error.HTTPError,
                                  discover, self.input_url)
        else:
            result = discover(self.input_url)
            self.assertEqual(self.input_url, result.request_uri)

            msg = 'Identity URL mismatch: actual = %r, expected = %r' % (
                result.normalized_uri, self.expected.normalized_uri)
            self.assertEqual(
                self.expected.normalized_uri, result.normalized_uri, msg)

            msg = 'Content mismatch: actual = %r, expected = %r' % (
                result.response_text, self.expected.response_text)
            self.assertEqual(
                self.expected.response_text, result.response_text, msg)

            expected_keys = dir(self.expected)
            expected_keys.sort()
            actual_keys = dir(result)
            actual_keys.sort()
            self.assertEqual(actual_keys, expected_keys)

            for k in dir(self.expected):
                if k.startswith('__') and k.endswith('__'):
                    continue
                exp_v = getattr(self.expected, k)
                if isinstance(exp_v, types.MethodType):
                    continue
                act_v = getattr(result, k)
                assert act_v == exp_v, (k, exp_v, act_v)

    def shortDescription(self):
        try:
            n = self.input_url
        except AttributeError:
            # run before setUp, or if setUp did not complete successfully.
            n = self.input_name
        return "%s (%s)" % (
            n,
            self.__class__.__module__)


def pyUnitTests():
    s = unittest.TestSuite()
    for success, input_name, id_name, result_name in discoverdata.testlist:
        test = _TestCase(input_name, id_name, result_name, success)
        s.addTest(test)

    return s


def test():
    runner = unittest.TextTestRunner()
    return runner.run(pyUnitTests())

if __name__ == '__main__':
    test()
