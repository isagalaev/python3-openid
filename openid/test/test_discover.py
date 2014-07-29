# -*- coding: utf-8 -*-
import unittest
from unittest import mock
import os.path
import urllib
from urllib.parse import urlsplit, urlencode, urljoin

from . import support
from .support import HTTPResponse

from openid import fetchers
from openid.yadis.discover import DiscoveryFailure
from openid.consumer import discover
from openid.yadis import xrires
from openid.yadis.xri import XRI
from openid import message


@mock.patch('urllib.request.urlopen', support.urlopen)
@support.gentests
class Failure(unittest.TestCase):
    data = [
        ('network_error', ('http://network.error/',)),
        ('not_found', ('/404',)),
        ('header_found', ('/200?' + urlencode({'header': 'X-XRDS-Location: http://unittest/404'}),)),
        ('server_error', ('/500',)),
    ]

    def _test(self, path):
        url = urljoin('http://unittest', path)
        self.assertRaises(urllib.error.URLError, discover.discover, url)


@mock.patch('urllib.request.urlopen', support.urlopen)
class Normalization(unittest.TestCase):
    def testAddingProtocol(self):
        url = 'unittest:8000/200'
        discover.discover(url)
        self.assertEqual(support.urlopen.request.get_full_url(), 'http://' + url)


class BaseTestDiscovery(unittest.TestCase):
    def _checkService(self, s,
                      server_url,
                      claimed_id=None,
                      local_id=None,
                      canonical_id=None,
                      types=None,
                      used_yadis=False,
                      display_identifier=None
                      ):
        self.assertEqual(server_url, s.server_url)
        if types == ['2.0 OP']:
            self.assertFalse(claimed_id)
            self.assertFalse(local_id)
            self.assertFalse(s.claimed_id)
            self.assertFalse(s.local_id)
            self.assertFalse(s.getLocalID())
            self.assertFalse(s.compatibilityMode())
            self.assertTrue(s.isOPIdentifier())
            self.assertEqual(s.preferredNamespace(),
                                 discover.OPENID_2_0_MESSAGE_NS)
        else:
            self.assertEqual(claimed_id, s.claimed_id)
            self.assertEqual(local_id, s.getLocalID())

        if used_yadis:
            self.assertTrue(s.used_yadis, "Expected to use Yadis")
        else:
            self.assertFalse(s.used_yadis,
                        "Expected to use old-style discovery")

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
            self.assertTrue(s.getDisplayIdentifier() != claimed_id)
            self.assertTrue(s.getDisplayIdentifier() is not None)
            self.assertEqual(display_identifier, s.getDisplayIdentifier())
            self.assertEqual(s.claimed_id, s.canonicalID)

        self.assertEqual(s.display_identifier or s.claimed_id,
                         s.getDisplayIdentifier())


def readDataFile(filename):
    """
    Read the contents of the given file and return them. NOTE that files are
    read in binary mode and the return value is a bytes object.
    """
    module_directory = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(support.DATAPATH, filename)
    with open(filename, 'rb') as f:
        contents = f.read()
    return contents

def fileurl(filename):
    return 'http://unittest/%s' % filename

@mock.patch('urllib.request.urlopen', support.urlopen)
class TestDiscovery(BaseTestDiscovery):
    def _discover(self, url, expected_service_count,
                  expected_id=None):
        if expected_id is None:
            expected_id = url
        id_url, services = discover.discover(url)
        self.assertEqual(expected_service_count, len(services))
        self.assertEqual(expected_id, id_url)
        return services

    def test_unicode(self):
        """
        Check page with unicode and HTML entities
        """
        self._discover(fileurl('unicode.html'),
            expected_service_count=0)

    def test_unicode_undecodable_html2(self):
        """
        Check page with unicode and HTML entities that can not be decoded
        but xrds document is found before it matters
        """
        data = readDataFile('unicode3.html')
        self.assertRaises(UnicodeDecodeError, data.decode, 'utf-8')
        self._discover(fileurl('unicode3.html'), expected_service_count=1)

    def test_noOpenID(self):
        services = self._discover(fileurl('junk.txt'), expected_service_count=0)

        url = fileurl('openid_no_delegate.html')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id=url,
            )

    def test_html1(self):
        url = fileurl('openid.html')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=url,
            )

    def test_html1Fragment(self):
        """Ensure that the Claimed Identifier does not have a fragment
        if one is supplied in the User Input."""
        url = fileurl('openid.html')
        expected_id = url
        url += '#fragment'
        id_url, services = discover.discover(url)
        self.assertEqual(len(services), 1)
        self.assertEqual(id_url, expected_id)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=expected_id,
            local_id='http://smoker.myopenid.com/',
            display_identifier=expected_id,
            )

    def test_html2(self):
        url = fileurl('openid2.html')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=url,
            )

    def test_html1And2(self):
        url = fileurl('openid_1_and_2.html')
        services = self._discover(url, expected_service_count=2)

        for t, s in zip(['2.0', '1.1'], services):
            self._checkService(
                s,
                used_yadis=False,
                types=[t],
                server_url="http://www.myopenid.com/server",
                claimed_id=url,
                local_id='http://smoker.myopenid.com/',
                display_identifier=url,
                )

    def test_yadisEmpty(self):
        services = self._discover(fileurl('yadis_0entries.xrds'),
                                  expected_service_count=0)

    def test_htmlEmptyYadis(self):
        """HTML document has discovery information, but points to an
        empty Yadis document."""
        # The XRDS document pointed to by "openid_and_yadis.html"
        url = fileurl('openid_and_yadis.html')
        services = self._discover(url, expected_service_count=1)
        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=url,
            )

    def test_yadis1NoDelegate(self):
        url = fileurl('yadis_no_delegate.xrds')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id=url,
            display_identifier=url,
            )

    def test_yadis2NoLocalID(self):
        url = fileurl('openid2_xrds_no_local_id.xrds')
        services = self._discover(url, expected_service_count=1)
        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id=url,
            display_identifier=url,
            )

    def test_yadis2(self):
        url = fileurl('openid2_xrds.xrds')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=url,
            )

    def test_yadis2OP(self):
        url = fileurl('yadis_idp.xrds')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            display_identifier=url,
            )

    def test_yadis2OPDelegate(self):
        """The delegate tag isn't meaningful for OP entries."""
        url = fileurl('yadis_idp_delegate.xrds')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            display_identifier=url,
            )

    def test_yadis2BadLocalID(self):
        with self.assertRaises(DiscoveryFailure):
            self._discover(
                fileurl('yadis_2_bad_local_id.xrds'),
                expected_service_count=1,
            )

    def test_yadis1And2(self):
        url = fileurl('openid_1_and_2_xrds.xrds')
        services = self._discover(url, expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0', '1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=url,
            )

    def test_yadis1And2BadLocalID(self):
        with self.assertRaises(DiscoveryFailure):
            self._discover(
                fileurl('openid_1_and_2_xrds_bad_delegate.xrds'),
                expected_service_count=1,
            )


@mock.patch('urllib.request.urlopen', support.urlopen)
class TestXRIDiscovery(BaseTestDiscovery):
    def test_xri(self):
        user_xri, services = discover.discoverXRI('=iname')

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://smoker.myopenid.com/',
            display_identifier='=iname'
            )

        self._checkService(
            services[1],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.livejournal.com/openid/server.bml",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://frank.livejournal.com/',
            display_identifier='=iname'
            )

    def test_xri_normalize(self):
        user_xri, services = discover.discoverXRI('xri://=iname')

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://smoker.myopenid.com/',
            display_identifier='=iname'
            )

        self._checkService(
            services[1],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.livejournal.com/openid/server.bml",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://frank.livejournal.com/',
            display_identifier='=iname'
            )

    def test_xriNoCanonicalID(self):
        user_xri, services = discover.discoverXRI('=iname*empty')
        self.assertFalse(services)

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = XRI("=!1000")
        endpoint.canonicalID = XRI("=!1000")
        self.assertEqual(endpoint.getLocalID(), XRI("=!1000"))


@mock.patch('urllib.request.urlopen', support.urlopen)
class TestXRIDiscoveryIDP(BaseTestDiscovery):
    def test_xri(self):
        user_xri, services = discover.discoverXRI('=iname.idp')
        self.assertTrue(services, "Expected services, got zero")
        self.assertEqual(services[0].server_url,
                             "http://www.livejournal.com/openid/server.bml")


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

    def test_strip_fragment(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = 'http://unittest/#123'
        self.assertEqual(endpoint.getDisplayIdentifier(), 'http://unittest/')


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
