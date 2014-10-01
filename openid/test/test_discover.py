# -*- coding: utf-8 -*-
import unittest
from unittest import mock
import os.path
import urllib.error
from urllib.parse import urlsplit, urlencode, urljoin

from openid import message
from openid.consumer import discover
from . import support


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
class Failure(unittest.TestCase):
    data = [
        ('network_error', ('http://network.error/',)),
        ('not_found', ('/404',)),
        ('header_found', ('/?' + urlencode({'header': 'X-XRDS-Location: http://unittest/404'}),)),
        ('server_error', ('/?status=500',)),
    ]

    def _test(self, path):
        url = urljoin('http://unittest', path)
        self.assertRaises(urllib.error.URLError, discover.discover, url)


@mock.patch('urllib.request.urlopen', support.urlopen)
class Discovery(unittest.TestCase):
    def test_unicode(self):
        """
        Check page with unicode and HTML entities
        """
        services = discover.discoverall('http://unittest/unicode.html')
        self.assertEqual(len(services), 0)

    def test_unicode_undecodable_html2(self):
        """
        Check page with unicode and HTML entities that can not be decoded
        but xrds document is found before it matters
        """
        with open(os.path.join(support.DATAPATH, 'unicode3.html'), encoding='utf-8') as f:
            self.assertRaises(UnicodeDecodeError, f.read)
        services = discover.discoverall('http://unittest/unicode3.html')
        self.assertEqual(len(services), 1)

    def test_noOpenID(self):
        services = discover.discoverall('http://unittest/junk.txt')
        self.assertFalse(services)

    def test_yadisEmpty(self):
        services = discover.discoverall('http://unittest/yadis_0entries.xrds')
        self.assertFalse(services)

    def test_html_yadis_empty(self):
        # The HTML document contains OpenID links but also refers to an empty Yadis
        # document which we should prefer, by the Yadis spec.
        services = discover.discoverall('http://unittest/openid_and_yadis.html')
        self.assertFalse(services)

    def test_xrds_with_header(self):
        # Even if we got a valid XRDS document but with a link to another XRDS
        # location we should prefer that location, by the Yadis spec.
        location_url = 'http://unittest/openid2_xrds.xrds'
        params = {'header': 'X-XRDS-Location: %s' % location_url}
        url = 'http://unittest/openid_1_and_2_xrds.xrds?' + urlencode(params)
        services = discover.discoverall(url)
        self.assertEqual(support.urlopen.request.get_full_url(), location_url)

    def test_fragment(self):
        url = 'http://unittest/openid.html'
        service = discover.discover(url + '#fragment')
        self.assertEqual(service.claimed_id, url)

    def test_add_protocol(self):
        url = 'unittest:8000/'
        discover.discoverall(url)
        self.assertEqual(support.urlopen.request.get_full_url(), 'http://' + url)

    def test_wrong_protocol(self):
        url = 'ssh://unittest/'
        self.assertRaises(discover.DiscoveryFailure, discover.discoverall, url)

    def test_html1And2(self):
        url = 'http://unittest/openid_1_and_2.html'
        services = discover.discoverall(url)
        self.assertEqual(len(services), 2)
        for s in services:
            self.assertEqual(s.server_url, 'http://www.myopenid.com/server')
            self.assertEqual(s.local_id, 'http://smoker.myopenid.com/')
            self.assertEqual(s.claimed_id, url)

    def test_service_sort(self):
        services = discover.discoverall('http://unittest/multiple_services.xrds')
        self.assertEqual(len(services), 3)
        self.assertTrue(discover.OPENID_IDP_2_0_TYPE in services[0].types)
        self.assertTrue(discover.OPENID_2_0_TYPE in services[1].types)
        self.assertTrue(discover.OPENID_1_0_TYPE in services[2].types)

    def test_redirected_claimed_id(self):
        claimed_id = 'http://unittest/openid2_xrds.xrds'
        url = 'http://unittest/200.txt?' + urlencode({'redirect': claimed_id})
        service = discover.discover(url)
        self.assertEqual(claimed_id, service.claimed_id)

    def test_xri_idp(self):
        service = discover.discover('=iname.idp')
        self.assertEqual(service.server_url, 'http://www.livejournal.com/openid/server.bml')

    def test_two_services(self):
        services = discover.discoverall('=twoservices')
        self.assertEqual(len(services), 2)
        self.assertTrue(services[0].local_id, 'http://smoker.myopenid.com/')
        self.assertTrue(services[1].local_id, 'http://frank.livejournal.com/')

    def test_xriNoCanonicalID(self):
        with self.assertLogs('', 'ERROR'):
            services = discover.discoverall('=iname*empty')
        self.assertFalse(services)


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
class Services(unittest.TestCase):
    data = [
        # arguments: url, types, claimed_id, local_id, canonical_id
        # last four arguments can be None, in which case the url is used instead
        ('no_delegate', ('http://unittest/openid_no_delegate.html', ['1.1'], None, None)),
        ('html1', ('http://unittest/openid.html', ['1.1'], None, 'http://smoker.myopenid.com/')),
        ('html2', ('http://unittest/openid2.html', ['2.0'], None, 'http://smoker.myopenid.com/')),
        ('yadis1_no_delegate', ('http://unittest/yadis_no_delegate.xrds', ['1.0'], None, None)),
        ('yadis2_no_local_id', ('http://unittest/openid2_xrds_no_local_id.xrds', ['2.0'], None, None)),
        ('yadis2', ('http://unittest/openid2_xrds.xrds', ['2.0'], None, 'http://smoker.myopenid.com/')),
        ('yadis2_op', ('http://unittest/yadis_idp.xrds', ['2.0 OP'], False, False)),
        ('yadis2_op_delegate', ('http://unittest/yadis_idp_delegate.xrds', ['2.0 OP'], False, False)),
        ('yadis1_and_2', ('http://unittest/openid_1_and_2_xrds.xrds', ['2.0', '1.1'], None, 'http://smoker.myopenid.com/')),
        ('xri', ('=iname', ['1.0'], '=!1000', 'http://smoker.myopenid.com/')),
        ('xri_normalize', ('xri://=iname', ['1.0'], '=!1000', 'http://smoker.myopenid.com/')),
    ]

    def _test(self, url, types, claimed_id, local_id):
        service = discover.discover(url)
        if claimed_id is None:
            claimed_id = url
        if local_id is None:
            local_id = url
        self.assertEqual(service.server_url, 'http://www.myopenid.com/server')
        if types == ['2.0 OP']:
            self.assertFalse(claimed_id)
            self.assertFalse(local_id)
            self.assertFalse(service.claimed_id)
            self.assertFalse(service.local_id)
            self.assertFalse(service.identity())
            self.assertFalse(service.compat_mode())
            self.assertTrue(service.is_op_identifier())
            self.assertEqual(service.ns(), discover.OPENID2_NS)
        else:
            self.assertEqual(claimed_id, service.claimed_id)
            self.assertEqual(local_id, service.identity())

        openid_types = {
            '1.1': discover.OPENID_1_1_TYPE,
            '1.0': discover.OPENID_1_0_TYPE,
            '2.0': discover.OPENID_2_0_TYPE,
            '2.0 OP': discover.OPENID_IDP_2_0_TYPE,
            }

        types = [openid_types[t] for t in types]
        self.assertEqual(types, service.types)


class Endpoint(unittest.TestCase):
    def test_openid_2(self):
        endpoint = discover.Service()
        self.assertFalse(endpoint.compat_mode())
        endpoint = discover.Service([discover.OPENID_2_0_TYPE])
        self.assertFalse(endpoint.compat_mode())
        endpoint = discover.Service([discover.OPENID_IDP_2_0_TYPE])
        self.assertFalse(endpoint.compat_mode())
        self.assertEqual(endpoint.ns(), discover.OPENID2_NS)

    def test_openid_1(self):
        endpoint = discover.Service([discover.OPENID_1_1_TYPE])
        self.assertTrue(endpoint.compat_mode())
        self.assertEqual(endpoint.ns(), discover.OPENID1_NS)

    def test_is_op_identifier(self):
        endpoint = discover.Service([
            discover.OPENID_2_0_TYPE,
            discover.OPENID_1_0_TYPE,
            discover.OPENID_1_1_TYPE,
        ])
        self.assertFalse(endpoint.is_op_identifier())
        endpoint = discover.Service([discover.OPENID_IDP_2_0_TYPE])
        self.assertTrue(endpoint.is_op_identifier())

    def test_local_id(self):
        endpoint = discover.Service(claimed_id='claimed_id')
        self.assertEqual(endpoint.identity(), 'claimed_id')
        endpoint = discover.Service(claimed_id='claimed_id', local_id='local_id')
        self.assertEqual(endpoint.identity(), 'local_id')
        endpoint = discover.Service()
        self.assertEqual(endpoint.identity(), None)


@support.gentests
class TestDiscoverFunction(unittest.TestCase):
    data = [
        ('uri', ('http://unittest', 'uri')),
        ('bogus', ('not a URL or XRI', 'uri')),
        ('xri', ('xri://=something', 'xri')),
        ('xri_char', ('=something', 'xri')),
    ]

    @mock.patch('openid.consumer.discover.discoverURI')
    @mock.patch('openid.consumer.discover.discoverXRI')
    def _test(self, value, target, xri, uri):
        discover.discoverall(value)
        hit, miss = (uri, xri) if target == 'uri' else (xri, uri)
        hit.assert_called_with(value)
        self.assertEqual(miss.call_count, 0)


if __name__ == '__main__':
    unittest.main()
