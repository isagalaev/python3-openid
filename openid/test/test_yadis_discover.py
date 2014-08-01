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


@mock.patch('urllib.request.urlopen', support.urlopen)
@gentests
class XRDS(unittest.TestCase):
    data = [
        ('xrds', ({},)),
        ('content_type_param', ({'header': 'Content-type: application/xrds+xml; charset=UTF8'},)),
        ('content_type_case', ({'header': 'Content-type: appliCATION/XRDS+xml'},)),
    ]

    def _test(self, params):
        url = 'http://unittest/openid_1_and_2_xrds.xrds?' + urllib.parse.urlencode(params)
        result = discover(url)
        self.assertTrue(result.isXRDS())


@mock.patch('urllib.request.urlopen', support.urlopen)
@gentests
class YadisLocation(unittest.TestCase):
    data = [
        ('header', ('/?' + urllib.parse.urlencode({'header': 'X-XRDS-Location: http://unittest/openid_1_and_2_xrds.xrds'}),)),
        ('lowercase', ('/?' + urllib.parse.urlencode({'header': 'x-xrds-location: http://unittest/openid_1_and_2_xrds.xrds'}),)),
        ('http_equiv', ('/http_equiv.html',)),
    ]
    def _test(self, path):
        url = urllib.parse.urljoin('http://unittest/', path)
        result = discover(url)
        self.assertTrue(result.usedYadisLocation())


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

    def test_wrong_content_type(self):
        params = {'header': 'Content-type: text/html'}
        url = 'http://unittest/openid_1_and_2_xrds.xrds?' + urllib.parse.urlencode(params)
        result = discover(url)
        self.assertFalse(result.isXRDS())


if __name__ == '__main__':
    unittest.main()
