import unittest
from unittest import mock
import urllib.parse
import urllib.error
import re
import types
import io

from openid.yadis.discover import discover

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


def make_response(data, url):
    status = int(STATUS_RE.search(data).group(1))
    headers_str, body = data.split('\n\n', 1)
    headers = dict(l.split(': ') for l in headers_str.split('\n'))
    return HTTPResponse(url, status, headers=headers, body=body.encode('utf-8'))


def fetch(url, body=None, headers=None):
    path = urllib.parse.urlparse(url).path.lstrip('/')
    try:
        data = discoverdata.generateSample(path, BASE_URL)
    except KeyError:
        data = '404 Not found\n\nNot found'

    response = make_response(data, url)
    if response.status >= 400:
        raise urllib.error.HTTPError(url, response.status, 'Test request failed', {}, io.BytesIO())
    if response.status in [301, 302, 303, 307]:
        return fetch(response.getheader('location'))
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
        if expected is None:
            self.assertRaises(urllib.error.HTTPError, discover, input_url)
        else:
            result = discover(input_url)
            self.assertEqual(input_url, result.request_uri)
            self.assertEqual(result.__dict__, expected.__dict__)

# Generation of test methods within Discover. They have predictable names,
# can be run individually and are discovered by standard unittest machinery.
for success, input_name, id_name, result_name in discoverdata.testlist:
    def g(*args):
        def test_method(self):
            self._test(*args)
        return test_method
    method = g(success, input_name, id_name, result_name)
    name = 'test_%s' % input_name
    method.__name__ = name
    setattr(Discover, name, method)


if __name__ == '__main__':
    unittest.main()
