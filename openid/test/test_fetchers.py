import unittest
from unittest import mock
import urllib.error

from openid import fetchers
from . import support


@mock.patch('urllib.request.urlopen', support.urlopen)
class Fetcher(unittest.TestCase):
    def test_success(self):
        url = 'http://%s/success' % support.TEST_HOST
        result = fetchers.fetch(url)
        self.assertEqual(result.url, url)
        self.assertEqual(result.status, 200)
        body = b'/success'
        self.assertEqual(result.read(), body)

    def test_bad_urls(self):
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'not-a-url')
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'http://unknown-host/')

    def test_disallowed(self):
        with mock.patch('urllib.request.urlopen') as support.urlopen:
            self.assertRaises(urllib.error.URLError, fetchers.fetch, 'ftp://localhost/')
            self.assertEqual(support.urlopen.call_count, 0)

    def test_http_errors(self):
        self.assertRaises(urllib.error.URLError, fetchers.fetch, 'http://%s/404' % support.TEST_HOST)

    def test_user_agent(self):
        fetchers.fetch('http://unittest/success')
        self.assertEqual(support.urlopen.request.get_header('User-agent'), fetchers.USER_AGENT)

    def test_post(self):
        body = b'body'
        fetchers.fetch('http://unittest/success', body, {'Content-length': len(body)})
        self.assertEqual(support.urlopen.request.data, body)


if __name__ == '__main__':
    unittest.main()
