import unittest
from unittest import mock
import urllib.parse
import urllib.error

from openid import xrds
from openid.yadis.discover import fetch_data
from . import support


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
class XRDS(unittest.TestCase):
    data = [
        ('xrds', ('/openid_1_and_2_xrds.xrds', {},)),
        ('ctype_param', ('/openid_1_and_2_xrds.xrds', {'header': 'Content-type: application/xrds+xml; charset=UTF8'},)),
        ('ctype_case', ('/openid_1_and_2_xrds.xrds', {'header': 'Content-type: appliCATION/XRDS+xml'},)),
        ('header', ('/', {'header': 'X-XRDS-Location: http://unittest/openid_1_and_2_xrds.xrds'},)),
        ('lowercase', ('/', {'header': 'x-xrds-location: http://unittest/openid_1_and_2_xrds.xrds'},)),
        ('http_equiv', ('/http_equiv.html', {})),
    ]
    def _test(self, path, params):
        if params:
            path += '?' + urllib.parse.urlencode(params)
        url = urllib.parse.urljoin('http://unittest/', path)
        doc = xrds.parseXRDS(fetch_data(url)[1])
        self.assertTrue(doc)


@mock.patch('urllib.request.urlopen', support.urlopen)
class Special(unittest.TestCase):
    def test_second_get(self):
        params = {'header': 'X-XRDS-Location: http://unittest/404'}
        url = 'http://unittest/?' + urllib.parse.urlencode(params)
        self.assertRaises(urllib.error.HTTPError, fetch_data, url)
        self.assertEqual(support.urlopen.request.get_full_url(), 'http://unittest/404')

    def test_exception(self):
        url = 'http://unittest/404'
        self.assertRaises(urllib.error.HTTPError, fetch_data, url)


if __name__ == '__main__':
    unittest.main()
