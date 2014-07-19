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


class TestSecondGet(unittest.TestCase):
    def test_404(self):
        location = 'http://unittest/404'
        fetch = mock.Mock(return_value=HTTPResponse('', 200, {'X-XRDS-Location': location}))
        with mock.patch('openid.fetchers.fetch', fetch):
            discover('http://something.unittest/')
        fetch.assert_called_with(location)
        self.assertEqual(fetch.call_count, 2)


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


class Discover(unittest.TestCase):

    @mock.patch('openid.fetchers.fetch', fetch)
    def _test(self, success, input_name, id_name, result_name):
        '''
        Common function called with different arguments from generated
        test methods.
        '''
        input_url, expected = discoverdata.generateResult(
            BASE_URL,
            input_name,
            id_name,
            result_name,
            success,
        )
        if expected is urllib.error.HTTPError:
            self.assertRaises(urllib.error.HTTPError, discover, input_url)
        else:
            result = discover(input_url)
            self.assertEqual(input_url, result.request_uri)

            msg = 'Identity URL mismatch: actual = %r, expected = %r' % (
                result.normalized_uri, expected.normalized_uri)
            self.assertEqual(
                expected.normalized_uri, result.normalized_uri, msg)

            msg = 'Content mismatch: actual = %r, expected = %r' % (
                result.response_text, expected.response_text)
            self.assertEqual(
                expected.response_text, result.response_text, msg)

            expected_keys = dir(expected)
            expected_keys.sort()
            actual_keys = dir(result)
            actual_keys.sort()
            self.assertEqual(actual_keys, expected_keys)

            for k in dir(expected):
                if k.startswith('__') and k.endswith('__'):
                    continue
                exp_v = getattr(expected, k)
                if isinstance(exp_v, types.MethodType):
                    continue
                act_v = getattr(result, k)
                assert act_v == exp_v, (k, exp_v, act_v)

# Generation of test methods within Discover. They have predictable names,
# can be run individually and are discovered by standard unittest machinery.
for success, input_name, id_name, result_name in discoverdata.testlist:
    def test_method(self):
        self._test(success, input_name, id_name, result_name)
    name = 'test_%s' % input_name
    test_method.__name__ = name
    setattr(Discover, name, test_method)


if __name__ == '__main__':
    unittest.main()
