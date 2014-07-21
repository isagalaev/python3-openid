import unittest
from unittest import mock
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlunparse
import io

from openid import fetchers

from .support import HTTPResponse


TEST_HOST = 'unittest'


def urlopen(request, data=None):
    if isinstance(request, str):
        request = urllib.request.Request(request)
    # track the last call arguments
    urlopen.request = request
    urlopen.data = data

    url = request.get_full_url()
    schema, server, path, params, query, fragment = urlparse(url)

    if server != TEST_HOST:
        raise urllib.error.URLError('Wrong host, expected: %s' % TEST_HOST)
    if path != '/success':
        raise urllib.error.HTTPError(url, 404, '', {}, io.BytesIO(b'Not found'))

    body = b'/success'
    headers = {
        'Server': 'Urlopen-Mock',
        'Date': 'Mon, 21 Jul 2014 19:52:42 GMT',
        'Content-type': 'text/plain',
        'Content-length': len(body),
    }
    return HTTPResponse(url, 200, headers, body)


@mock.patch('urllib.request.urlopen', urlopen)
class Fetcher(unittest.TestCase):
    def test_success(self):
        url = 'http://%s/success' % TEST_HOST
        result = fetchers.fetch(url)
        self.assertEqual(result.url, url)
        self.assertEqual(result.status, 200)
        body = b'/success'
        self.assertEqual(result.read(), body)

    def test_bad_urls(self):
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'not-a-url')
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'http://unknown-host/')

    def test_disallowed(self):
        with mock.patch('urllib.request.urlopen') as urlopen:
            self.assertRaises(urllib.error.URLError, fetchers.fetch, 'ftp://localhost/')
            self.assertEqual(urlopen.call_count, 0)

    def test_http_errors(self):
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'http://%s/404' % TEST_HOST)

    def test_user_agent(self):
        fetchers.fetch('http://unittest/success')
        self.assertEqual(urlopen.request.get_header('User-agent'), fetchers.USER_AGENT)

    def test_post(self):
        body = b'body'
        fetchers.fetch('http://unittest/success', body, {'Content-length': len(body)})
        self.assertEqual(urlopen.request.data, body)


if __name__ == '__main__':
    unittest.main()
