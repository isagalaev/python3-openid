import unittest
from unittest import mock
import urllib.parse
import urllib.error

from openid.yadis.discover import discover
from . import support


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
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
@support.gentests
class Location(unittest.TestCase):
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
