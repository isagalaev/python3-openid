# -*- coding: utf-8 -*-
import unittest
from unittest import mock
import os.path
import urllib.error
from urllib.parse import urlsplit, urlencode, urljoin

from . import support
from openid.yadis.discover import DiscoveryFailure
from openid.consumer import discover
from openid.yadis.xri import XRI
from openid import message


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
        id_url, services = discover.discover('http://unittest/unicode.html')
        self.assertEqual(len(services), 0)

    def test_unicode_undecodable_html2(self):
        """
        Check page with unicode and HTML entities that can not be decoded
        but xrds document is found before it matters
        """
        with open(os.path.join(support.DATAPATH, 'unicode3.html'), encoding='utf-8') as f:
            self.assertRaises(UnicodeDecodeError, f.read)
        id_url, services = discover.discover('http://unittest/unicode3.html')
        self.assertEqual(len(services), 1)

    def test_noOpenID(self):
        url, services = discover.discover('http://unittest/junk.txt')
        self.assertFalse(services)

    def test_yadisEmpty(self):
        url, services = discover.discover('http://unittest/yadis_0entries.xrds')
        self.assertFalse(services)

    def test_html_yadis_empty(self):
        # The HTML document contains OpenID links but also refers to an empty Yadis
        # document which we should prefer, by the Yadis spec.
        url, services = discover.discover('http://unittest/openid_and_yadis.html')
        self.assertFalse(services)

    def test_xrds_with_header(self):
        # Even if we got a valid XRDS document but with a link to another XRDS
        # location we should prefer that location, by the Yadis spec.
        location_url = 'http://unittest/openid2_xrds.xrds'
        params = {'header': 'X-XRDS-Location: %s' % location_url}
        url = 'http://unittest/openid_1_and_2_xrds.xrds?' + urlencode(params)
        url, services = discover.discover(url)
        self.assertEqual(support.urlopen.request.get_full_url(), location_url)

    def test_fragment(self):
        url = 'http://unittest/openid.html'
        id_url, services = discover.discover(url + '#fragment')
        self.assertEqual(id_url, url)
        self.assertEqual(services[0].claimed_id, url)

    def test_add_protocol(self):
        url = 'unittest:8000/'
        discover.discover(url)
        self.assertEqual(support.urlopen.request.get_full_url(), 'http://' + url)

    def test_localid_mismatch(self):
        with self.assertRaises(DiscoveryFailure):
            discover.discover('http://unittest/openid_1_and_2_xrds_bad_delegate.xrds')

    def test_html1And2(self):
        url = 'http://unittest/openid_1_and_2.html'
        id_url, services = discover.discover(url)
        self.assertEqual(len(services), 2)
        for s in services:
            self.assertEqual(s.server_url, 'http://www.myopenid.com/server')
            self.assertEqual(s.local_id, 'http://smoker.myopenid.com/')
            self.assertEqual(s.claimed_id, url)

    def test_xri_idp(self):
        user_xri, services = discover.discover('=iname.idp')
        self.assertTrue(services)
        self.assertEqual(services[0].server_url, 'http://www.livejournal.com/openid/server.bml')

    def test_two_services(self):
        xri, services = discover.discover('=twoservices')
        self.assertEqual(len(services), 2)
        self.assertTrue(services[0].local_id, 'http://smoker.myopenid.com/')
        self.assertTrue(services[1].local_id, 'http://frank.livejournal.com/')

    def test_xriNoCanonicalID(self):
        with self.assertLogs('', 'ERROR'):
            user_xri, services = discover.discover('=iname*empty')
        self.assertFalse(services)


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
class Services(unittest.TestCase):
    data = [
        # arguments: url, types, claimed_id, local_id, canonical_id
        # last four arguments can be None, in which case the url is used instead
        ('no_delegate', ('http://unittest/openid_no_delegate.html', ['1.1'], None, None, None)),
        ('html1', ('http://unittest/openid.html', ['1.1'], None, 'http://smoker.myopenid.com/', None)),
        ('html2', ('http://unittest/openid2.html', ['2.0'], None, 'http://smoker.myopenid.com/', None)),
        ('yadis1_no_delegate', ('http://unittest/yadis_no_delegate.xrds', ['1.0'], None, None, None)),
        ('yadis2_no_local_id', ('http://unittest/openid2_xrds_no_local_id.xrds', ['2.0'], None, None, None)),
        ('yadis2', ('http://unittest/openid2_xrds.xrds', ['2.0'], None, 'http://smoker.myopenid.com/', None)),
        ('yadis2_op', ('http://unittest/yadis_idp.xrds', ['2.0 OP'], False, False, None)),
        ('yadis2_op_delegate', ('http://unittest/yadis_idp_delegate.xrds', ['2.0 OP'], False, False, None)),
        ('yadis1_and_2', ('http://unittest/openid_1_and_2_xrds.xrds', ['2.0', '1.1'], None, 'http://smoker.myopenid.com/', None)),
        ('xri', ('=iname', ['1.0'], XRI("=!1000"), 'http://smoker.myopenid.com/', XRI("=!1000"))),
        ('xri_normalize', ('xri://=iname', ['1.0'], XRI('=!1000'), 'http://smoker.myopenid.com/', XRI('=!1000'))),
    ]

    def _test(self, url, types, claimed_id, local_id, canonical_id):
        id_url, services = discover.discover(url)
        # Disabled because XRI test return 4 services instead of 1 — possibly a bug
        self.assertEqual(len(services), 1)
        if claimed_id is None:
            claimed_id = url
        if local_id is None:
            local_id = url
        s = services[0]
        self.assertEqual(s.server_url, 'http://www.myopenid.com/server')
        if types == ['2.0 OP']:
            self.assertFalse(claimed_id)
            self.assertFalse(local_id)
            self.assertFalse(s.claimed_id)
            self.assertFalse(s.local_id)
            self.assertFalse(s.getLocalID())
            self.assertFalse(s.compatibilityMode())
            self.assertTrue(s.isOPIdentifier())
            self.assertEqual(s.preferredNamespace(), discover.OPENID2_NS)
        else:
            self.assertEqual(claimed_id, s.claimed_id)
            self.assertEqual(local_id, s.getLocalID())

        openid_types = {
            '1.1': discover.OPENID_1_1_TYPE,
            '1.0': discover.OPENID_1_0_TYPE,
            '2.0': discover.OPENID_2_0_TYPE,
            '2.0 OP': discover.OPENID_IDP_2_0_TYPE,
            }

        type_uris = [openid_types[t] for t in types]
        self.assertEqual(type_uris, s.type_uris)
        self.assertEqual(canonical_id, s.canonicalID)

        if s.canonicalID:
            self.assertEqual(s.claimed_id, s.canonicalID)


@support.gentests
class PreferredNamespace(unittest.TestCase):
    data = [
        ('empty', (message.OPENID1_NS, [])),
        ('bogus', (message.OPENID1_NS, ['http://unittest/'])),
        ('openid10', (message.OPENID1_NS, [discover.OPENID_1_0_TYPE])),
        ('openid11', (message.OPENID1_NS, [discover.OPENID_1_1_TYPE])),
        ('openid20', (message.OPENID2_NS, [discover.OPENID_2_0_TYPE])),
        ('openid20idp', (message.OPENID2_NS, [discover.OPENID_IDP_2_0_TYPE])),
        ('openid2and1', (message.OPENID2_NS, [discover.OPENID_2_0_TYPE, discover.OPENID_1_0_TYPE])),
        ('openid1and2', (message.OPENID2_NS, [discover.OPENID_1_0_TYPE, discover.OPENID_2_0_TYPE])),
    ]

    def _test(self, ns, type_uris):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.type_uris = type_uris
        self.assertEqual(ns, endpoint.preferredNamespace())


class Endpoint(unittest.TestCase):
    def test_isOPIdentifier(self):
        endpoint = discover.OpenIDServiceEndpoint()
        self.assertFalse(endpoint.isOPIdentifier())
        endpoint.type_uris = [
            discover.OPENID_2_0_TYPE,
            discover.OPENID_1_0_TYPE,
            discover.OPENID_1_1_TYPE,
        ]
        self.assertFalse(endpoint.isOPIdentifier())
        endpoint.type_uris.append(discover.OPENID_IDP_2_0_TYPE)
        self.assertTrue(endpoint.isOPIdentifier())

    def test_fromOPEndpointURL(self):
        url = 'http://example.com/op/endpoint'
        endpoint = discover.OpenIDServiceEndpoint.fromOPEndpointURL(url)
        self.assertTrue(endpoint.isOPIdentifier())
        self.assertEqual(endpoint.getLocalID(), None)
        self.assertEqual(endpoint.claimed_id, None)
        self.assertFalse(endpoint.compatibilityMode())
        self.assertEqual(endpoint.canonicalID, None)
        self.assertEqual(endpoint.server_url, url)

    def test_supportsType(self):
        endpoint = discover.OpenIDServiceEndpoint()
        self.assertFalse(endpoint.supportsType(discover.OPENID_2_0_TYPE))
        endpoint.type_uris = [discover.OPENID_2_0_TYPE]
        self.assertTrue(endpoint.supportsType(discover.OPENID_2_0_TYPE))
        # Should implicitly support this:
        endpoint.type_uris = [discover.OPENID_IDP_2_0_TYPE]
        self.assertTrue(endpoint.supportsType(discover.OPENID_2_0_TYPE))

    def test_uri_display_id(self):
        endpoint = discover.OpenIDServiceEndpoint()
        self.assertEqual(endpoint.display_id(), '')
        endpoint.claimed_id = 'http://unittest/'
        self.assertEqual(endpoint.display_id(), 'http://unittest/')

    def test_xri_display_id(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = '=iname'
        endpoint.canonicalID = '=!1000'
        self.assertEqual(endpoint.display_id(), '=iname')

    def test_strip_fragment(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = 'http://unittest/#123'
        self.assertEqual(endpoint.display_id(), 'http://unittest/')

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = XRI("=!1000")
        endpoint.canonicalID = XRI("=!1000")
        self.assertEqual(endpoint.getLocalID(), XRI("=!1000"))


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
        discover.discover(value)
        hit, miss = (uri, xri) if target == 'uri' else (xri, uri)
        hit.assert_called_with(value)
        self.assertEqual(miss.call_count, 0)


if __name__ == '__main__':
    unittest.main()
