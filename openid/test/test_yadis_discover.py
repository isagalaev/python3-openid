#!/usr/bin/env python
"""Tests for yadis.discover.

@todo: Now that yadis.discover uses urljr.fetchers, we should be able to do
   tests with a mock fetcher instead of spawning threads with BaseHTTPServer.
"""

import unittest
from unittest import mock
import urllib.parse
import urllib.error
import re
import types
import io

from openid.yadis.discover import discover, DiscoveryFailure

from . import discoverdata
from .support import HTTPResponse


STATUS_RE = re.compile(r'^Status: (\d+) .+\n')
BASE_URL = 'http://invalid.unittest/'


def mkResponse(data):
    status = int(STATUS_RE.search(data).group(1))
    headers_str, body = data.split('\n\n', 1)
    headers = dict(l.split(': ') for l in headers_str.split('\n'))
    return HTTPResponse('<test>', status, headers=headers, body=body.encode('utf-8'))


def fetch(url, body=None, headers=None):
    current_url = url
    while True:
        parsed = urllib.parse.urlparse(current_url)
        path = parsed[2][1:]
        try:
            data = discoverdata.generateSample(path, BASE_URL)
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
    def test_404(self):
        location = 'http://unittest/404'
        fetch = mock.Mock(return_value=HTTPResponse('', 200, {'X-XRDS-Location': location}))
        with mock.patch('openid.fetchers.fetch', fetch):
            discover('http://something.unittest/')
        fetch.assert_called_with(location)
        self.assertEqual(fetch.call_count, 2)


class _TestCase(unittest.TestCase):
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
        self.input_url, self.expected = discoverdata.generateResult(
            BASE_URL,
            self.input_name,
            self.id_name,
            self.result_name,
            self.success)

    @mock.patch('openid.fetchers.fetch', fetch)
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
