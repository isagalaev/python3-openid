import unittest
from unittest import mock
import urllib.parse
import urllib.error
import re
import types
import io

from openid.yadis.discover import discover

from . import discoverdata, support
from .support import gentests, HTTPResponse


STATUS_RE = re.compile(r'^Status: (\d+) .+\n')
BASE_URL = 'http://invalid.unittest/'


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
    data = [
        # args: success, input_name, id_name, result_name
        ("lowercase_header",    (True, "lowercase_header", "lowercase_header" , "xrds")),
        ("xrds",                (True, "xrds", "xrds" , "xrds")),
        ("xrds_ctparam",        (True, "xrds_ctparam", "xrds_ctparam" , "xrds_ctparam")),
        ("xrds_ctcase",         (True, "xrds_ctcase", "xrds_ctcase" , "xrds_ctcase")),
        ("xrds_html",           (False, "xrds_html", "xrds_html" , "xrds_html")),
    ]

    @mock.patch('openid.fetchers.fetch', fetch)
    def _test(self, success, input_name, id_name, result_name):
        input_url, expected = discoverdata.generateResult(
            BASE_URL,
            input_name,
            id_name,
            result_name,
            success,
        )
        result = discover(input_url)
        self.assertEqual(input_url, result.request_uri)
        self.assertEqual(result.__dict__, expected.__dict__)


@mock.patch('urllib.request.urlopen', support.urlopen)
@gentests
class YadisLocation(unittest.TestCase):
    data = [
        ('header', ('/?' + urllib.parse.urlencode({'header': 'X-XRDS-Location: http://unittest/openid_1_and_2_xrds.xrds'}),)),
        ('http_equiv', ('/http_equiv.html',)),
    ]
    def _test(self, path):
        url = urllib.parse.urljoin('http://unittest/', path)
        result = discover(url)
        self.assertTrue(result.usedYadisLocation())
        self.assertEqual(result.content_type, 'application/xrds+xml')


@mock.patch('urllib.request.urlopen', support.urlopen)
class Special(unittest.TestCase):
    def test_second_get(self):
        params = {'header': 'X-XRDS-Location: http://unittest/404'}
        url = 'http://unittest/?' + urllib.parse.urlencode(params)
        self.assertRaises(urllib.error.HTTPError, discover, url)
        self.assertEqual(support.urlopen.request.get_full_url(), 'http://unittest/404')

    def test_exception(self):
        url = 'http://unittest/404'
        self.assertRaises(urllib.error.HTTPError, discover, url)


if __name__ == '__main__':
    unittest.main()
