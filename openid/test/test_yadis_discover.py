import unittest
from unittest import mock
import urllib.parse
import urllib.error
import re
import types
import io

from openid.yadis.discover import discover

from . import discoverdata
from .support import gentests, HTTPResponse


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
    if 300 <= response.status < 400:
        return fetch(response.getheader('location'))
    elif 400 <= response.status:
        raise urllib.error.HTTPError(url, response.status, 'Test request failed', {}, io.BytesIO())
    else:
        return response


@gentests
class Discover(unittest.TestCase):
    data = discoverdata.testlist

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


if __name__ == '__main__':
    unittest.main()
