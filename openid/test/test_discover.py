# -*- coding: utf-8 -*-
import sys
import unittest
from unittest import mock
import os.path
import urllib
from urllib.parse import urlsplit, urlencode, urljoin

from . import datadriven, support
from .support import HTTPResponse

from openid import fetchers
from openid.yadis.discover import DiscoveryFailure
from openid.consumer import discover, consumer as openid_consumer
from openid.yadis import xrires
from openid.yadis.xri import XRI
from openid import message
import openid.store.memstore


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


class DiscoveryMockFetcher(object):
    redirect = None

    def __init__(self, documents):
        self.documents = documents
        self.fetchlog = []

    def fetch(self, url, body=None, headers=None):
        self.fetchlog.append((url, body, headers))
        if self.redirect:
            final_url = self.redirect
        else:
            final_url = url

        try:
            ctype, body = self.documents[url]
        except KeyError:
            status = 404
            ctype = 'text/plain'
            body = b''
        else:
            status = 200

        return HTTPResponse(final_url, status, {'content-type': ctype}, body)

# from twisted.trial import unittest as trialtest


class BaseTestDiscovery(unittest.TestCase):
    id_url = "http://someuser.unittest/"

    documents = {}
    fetcherClass = DiscoveryMockFetcher

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

    def setUp(self):
        self.documents = self.documents.copy()
        self.fetcher = self.fetcherClass(self.documents)
        self._original = fetchers.fetch
        fetchers.fetch = self.fetcher.fetch

    def tearDown(self):
        fetchers.fetch = self._original


def readDataFile(filename):
    """
    Read the contents of the given file and return them. NOTE that files are
    read in binary mode and the return value is a bytes object.
    """
    module_directory = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(
        module_directory, 'data', 'test_discover', filename)
    with open(filename, 'rb') as f:
        contents = f.read()
    return contents


class TestDiscovery(BaseTestDiscovery):
    def _discover(self, content_type, data, expected_service_count,
                  expected_id=None):
        if expected_id is None:
            expected_id = self.id_url

        self.documents[self.id_url] = (content_type, data)
        id_url, services = discover.discover(self.id_url)
        self.assertEqual(expected_service_count, len(services))
        self.assertEqual(expected_id, id_url)
        return services

    def test_unicode(self):
        """
        Check page with unicode and HTML entities
        """
        self._discover(
            content_type='text/html;charset=utf-8',
            data=readDataFile('unicode.html'),
            expected_service_count=0)

    def test_unicode_undecodable_html2(self):
        """
        Check page with unicode and HTML entities that can not be decoded
        but xrds document is found before it matters
        """
        self.documents[self.id_url + 'xrds'] = (
            'application/xrds+xml', readDataFile('yadis_idp.xml'))

        data = readDataFile('unicode3.html')
        self.assertRaises(UnicodeDecodeError, data.decode, 'utf-8')
        self._discover(content_type='text/html;charset=utf-8',
                       data=data, expected_service_count=1)

    def test_noOpenID(self):
        services = self._discover(content_type='text/plain',
                                  data=b'junk',
                                  expected_service_count=0)

        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid_no_delegate.html'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            )

    def test_html1(self):
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid.html'),
            expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=self.id_url,
            )

    def test_html1Fragment(self):
        """Ensure that the Claimed Identifier does not have a fragment
        if one is supplied in the User Input."""
        content_type = 'text/html'
        data = readDataFile('openid.html')
        expected_service_count = 1

        self.documents[self.id_url] = (content_type, data)
        expected_id = self.id_url
        self.id_url = self.id_url + '#fragment'
        id_url, services = discover.discover(self.id_url)
        self.assertEqual(expected_service_count, len(services))
        self.assertEqual(expected_id, id_url)

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
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid2.html'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=False,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=self.id_url,
            )

    def test_html1And2(self):
        services = self._discover(
            content_type='text/html',
            data=readDataFile('openid_1_and_2.html'),
            expected_service_count=2,
            )

        for t, s in zip(['2.0', '1.1'], services):
            self._checkService(
                s,
                used_yadis=False,
                types=[t],
                server_url="http://www.myopenid.com/server",
                claimed_id=self.id_url,
                local_id='http://smoker.myopenid.com/',
                display_identifier=self.id_url,
                )

    def test_yadisEmpty(self):
        services = self._discover(content_type='application/xrds+xml',
                                  data=readDataFile('yadis_0entries.xml'),
                                  expected_service_count=0)

    def test_htmlEmptyYadis(self):
        """HTML document has discovery information, but points to an
        empty Yadis document."""
        # The XRDS document pointed to by "openid_and_yadis.html"
        self.documents[self.id_url + 'xrds'] = (
            'application/xrds+xml', readDataFile('yadis_0entries.xml'))

        services = self._discover(content_type='text/html',
                                  data=readDataFile('openid_and_yadis.html'),
                                  expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=False,
            types=['1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=self.id_url,
            )

    def test_yadis1NoDelegate(self):
        services = self._discover(content_type='application/xrds+xml',
                                  data=readDataFile('yadis_no_delegate.xml'),
                                  expected_service_count=1)

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            display_identifier=self.id_url,
            )

    def test_yadis2NoLocalID(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid2_xrds_no_local_id.xml'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id=self.id_url,
            display_identifier=self.id_url,
            )

    def test_yadis2(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid2_xrds.xml'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=self.id_url,
            )

    def test_yadis2OP(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('yadis_idp.xml'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            display_identifier=self.id_url,
            )

    def test_yadis2OPDelegate(self):
        """The delegate tag isn't meaningful for OP entries."""
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('yadis_idp_delegate.xml'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0 OP'],
            server_url="http://www.myopenid.com/server",
            display_identifier=self.id_url,
            )

    def test_yadis2BadLocalID(self):
        self.assertRaises(DiscoveryFailure, self._discover,
            content_type='application/xrds+xml',
            data=readDataFile('yadis_2_bad_local_id.xml'),
            expected_service_count=1,
            )

    def test_yadis1And2(self):
        services = self._discover(
            content_type='application/xrds+xml',
            data=readDataFile('openid_1_and_2_xrds.xml'),
            expected_service_count=1,
            )

        self._checkService(
            services[0],
            used_yadis=True,
            types=['2.0', '1.1'],
            server_url="http://www.myopenid.com/server",
            claimed_id=self.id_url,
            local_id='http://smoker.myopenid.com/',
            display_identifier=self.id_url,
            )

    def test_yadis1And2BadLocalID(self):
        self.assertRaises(DiscoveryFailure, self._discover,
            content_type='application/xrds+xml',
            data=readDataFile('openid_1_and_2_xrds_bad_delegate.xml'),
            expected_service_count=1,
            )


class MockFetcherForXRIProxy(object):

    def __init__(self, documents, proxy_url=xrires.DEFAULT_PROXY):
        self.documents = documents
        self.fetchlog = []
        self.proxy_url = None

    def fetch(self, url, body=None, headers=None):
        self.fetchlog.append((url, body, headers))

        u = urlsplit(url)
        proxy_host = u[1]
        xri = u[2]
        query = u[3]

        if not headers and not query:
            raise ValueError("No headers or query; you probably didn't "
                             "mean to do that.")

        if xri.startswith('/'):
            xri = xri[1:]

        try:
            ctype, body = self.documents[xri]
        except KeyError:
            status = 404
            ctype = 'text/plain'
            body = ''
        else:
            status = 200

        return HTTPResponse(url, status, {'content-type': ctype}, body)


class TestXRIDiscovery(BaseTestDiscovery):
    fetcherClass = MockFetcherForXRIProxy

    documents = {'=smoker': ('application/xrds+xml',
                             readDataFile('yadis_2entries_delegate.xml')),
                 '=smoker*bad': ('application/xrds+xml',
                                 readDataFile('yadis_another_delegate.xml'))}

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://smoker.myopenid.com/',
            display_identifier='=smoker'
            )

        self._checkService(
            services[1],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.livejournal.com/openid/server.bml",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://frank.livejournal.com/',
            display_identifier='=smoker'
            )

    def test_xri_normalize(self):
        user_xri, services = discover.discoverXRI('xri://=smoker')

        self._checkService(
            services[0],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.myopenid.com/server",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://smoker.myopenid.com/',
            display_identifier='=smoker'
            )

        self._checkService(
            services[1],
            used_yadis=True,
            types=['1.0'],
            server_url="http://www.livejournal.com/openid/server.bml",
            claimed_id=XRI("=!1000"),
            canonical_id=XRI("=!1000"),
            local_id='http://frank.livejournal.com/',
            display_identifier='=smoker'
            )

    def test_xriNoCanonicalID(self):
        user_xri, services = discover.discoverXRI('=smoker*bad')
        self.assertFalse(services)

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = XRI("=!1000")
        endpoint.canonicalID = XRI("=!1000")
        self.assertEqual(endpoint.getLocalID(), XRI("=!1000"))


class TestXRIDiscoveryIDP(BaseTestDiscovery):
    fetcherClass = MockFetcherForXRIProxy

    documents = {'=smoker': ('application/xrds+xml',
                             readDataFile('yadis_2entries_idp.xml'))}

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')
        self.assertTrue(services, "Expected services, got zero")
        self.assertEqual(services[0].server_url,
                             "http://www.livejournal.com/openid/server.bml")


class TestPreferredNamespace(datadriven.DataDrivenTestCase):
    def __init__(self, expected_ns, type_uris):
        datadriven.DataDrivenTestCase.__init__(
            self, 'Expecting %s from %s' % (expected_ns, type_uris))
        self.expected_ns = expected_ns
        self.type_uris = type_uris

    def runOneTest(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.type_uris = self.type_uris
        actual_ns = endpoint.preferredNamespace()
        self.assertEqual(actual_ns, self.expected_ns)

    cases = [
        (message.OPENID1_NS, []),
        (message.OPENID1_NS, ['http://jyte.com/']),
        (message.OPENID1_NS, [discover.OPENID_1_0_TYPE]),
        (message.OPENID1_NS, [discover.OPENID_1_1_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_IDP_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE,
                              discover.OPENID_1_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_1_0_TYPE,
                              discover.OPENID_2_0_TYPE]),
        ]


class TestIsOPIdentifier(unittest.TestCase):
    def setUp(self):
        self.endpoint = discover.OpenIDServiceEndpoint()

    def test_isOPIdentifier(self):
        self.assertFalse(self.endpoint.isOPIdentifier())
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE,
                                   discover.OPENID_1_0_TYPE,
                                   discover.OPENID_1_1_TYPE]
        self.assertFalse(self.endpoint.isOPIdentifier())
        self.endpoint.type_uris.append(discover.OPENID_IDP_2_0_TYPE)
        self.assertTrue(self.endpoint.isOPIdentifier())


class TestFromOPEndpointURL(unittest.TestCase):
    def setUp(self):
        self.op_endpoint_url = 'http://example.com/op/endpoint'
        self.endpoint = discover.OpenIDServiceEndpoint.fromOPEndpointURL(
            self.op_endpoint_url)

    def test_isOPEndpoint(self):
        self.assertTrue(self.endpoint.isOPIdentifier())

    def test_noIdentifiers(self):
        self.assertEqual(self.endpoint.getLocalID(), None)
        self.assertEqual(self.endpoint.claimed_id, None)

    def test_compatibility(self):
        self.assertFalse(self.endpoint.compatibilityMode())

    def test_canonicalID(self):
        self.assertEqual(self.endpoint.canonicalID, None)

    def test_serverURL(self):
        self.assertEqual(self.endpoint.server_url, self.op_endpoint_url)


class TestDiscoverFunction(unittest.TestCase):
    def setUp(self):
        self._old_discoverURI = discover.discoverURI
        self._old_discoverXRI = discover.discoverXRI

        discover.discoverXRI = self.discoverXRI
        discover.discoverURI = self.discoverURI

    def tearDown(self):
        discover.discoverURI = self._old_discoverURI
        discover.discoverXRI = self._old_discoverXRI

    def discoverXRI(self, identifier):
        return 'XRI'

    def discoverURI(self, identifier):
        return 'URI'

    def test_uri(self):
        self.assertEqual('URI', discover.discover('http://woo!'))

    def test_uriForBogus(self):
        self.assertEqual('URI', discover.discover('not a URL or XRI'))

    def test_xri(self):
        self.assertEqual('XRI', discover.discover('xri://=something'))

    def test_xriChar(self):
        self.assertEqual('XRI', discover.discover('=something'))


class TestEndpointSupportsType(unittest.TestCase):
    def setUp(self):
        self.endpoint = discover.OpenIDServiceEndpoint()

    def failUnlessSupportsOnly(self, *types):
        for t in [
            'foo',
            discover.OPENID_1_1_TYPE,
            discover.OPENID_1_0_TYPE,
            discover.OPENID_2_0_TYPE,
            discover.OPENID_IDP_2_0_TYPE,
            ]:
            if t in types:
                self.assertTrue(self.endpoint.supportsType(t),
                                "Must support %r" % (t,))
            else:
                self.assertFalse(self.endpoint.supportsType(t),
                            "Shouldn't support %r" % (t,))

    def test_supportsNothing(self):
        self.failUnlessSupportsOnly()

    def test_openid2(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_2_0_TYPE)

    def test_openid2provider(self):
        self.endpoint.type_uris = [discover.OPENID_IDP_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_IDP_2_0_TYPE,
                                    discover.OPENID_2_0_TYPE)

    def test_openid1_0(self):
        self.endpoint.type_uris = [discover.OPENID_1_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_0_TYPE)

    def test_openid1_1(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE)

    def test_multiple(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE,
                                   discover.OPENID_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE,
                                    discover.OPENID_2_0_TYPE)

    def test_multipleWithProvider(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE,
                                   discover.OPENID_2_0_TYPE,
                                   discover.OPENID_IDP_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE,
                                    discover.OPENID_2_0_TYPE,
                                    discover.OPENID_IDP_2_0_TYPE,
                                    )


class TestEndpointDisplayIdentifier(unittest.TestCase):
    def test_strip_fragment(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = 'http://recycled.invalid/#123'
        self.assertEqual('http://recycled.invalid/',
                         endpoint.getDisplayIdentifier())


class TestDiscoveryFailureDjangoAllAuth(unittest.TestCase):
    def test_discovery(self):
        session = {}
        store = openid.store.memstore.MemoryStore()
        client = openid_consumer.Consumer(session, store)
        # Now confirm that trying discovery on a non-OpenID URL raises a
        # DiscoveryFailure
        with self.assertRaises(DiscoveryFailure):
            auth_request = client.begin("http://www.google.com")
            result = auth_request.redirectURL(
                'http://localhost/',
                'http://localhost/callback')
            self.assertEquals(result, None)


def pyUnitTests():
    suite = datadriven.loadTests(__name__)
    return suite


if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)
