"""Unit tests for verification of return_to URLs for a realm
"""
import unittest
from unittest import mock

from openid.yadis.discover import DiscoveryFailure
from openid.yadis import services, etxrd
from openid.server import trustroot
from openid.test.support import CatchLogs

from . import support


# Too many methods does not apply to unit test objects
#pylint:disable-msg=R0904
class TestBuildDiscoveryURL(unittest.TestCase):
    """Tests for building the discovery URL from a realm and a
    return_to URL
    """

    def failUnlessDiscoURL(self, realm, expected_discovery_url):
        """Build a discovery URL out of the realm and a return_to and
        make sure that it matches the expected discovery URL
        """
        realm_obj = trustroot.TrustRoot.parse(realm)
        actual_discovery_url = realm_obj.buildDiscoveryURL()
        self.assertEqual(expected_discovery_url, actual_discovery_url)

    def test_trivial(self):
        """There is no wildcard and the realm is the same as the return_to URL
        """
        self.failUnlessDiscoURL('http://example.com/foo',
                                'http://example.com/foo')

    def test_wildcard(self):
        """There is a wildcard
        """
        self.failUnlessDiscoURL('http://*.example.com/foo',
                                'http://www.example.com/foo')

@mock.patch('urllib.request.urlopen', support.urlopen)
class TestExtractReturnToURLs(unittest.TestCase):

    def failUnlessXRDSHasReturnURLs(self, url, expected_return_urls):
        actual_return_urls = list(trustroot.getAllowedReturnURLs(url))
        self.assertEqual(expected_return_urls, actual_return_urls)

    def test_no_entries(self):

        self.failUnlessXRDSHasReturnURLs('http://unittest/yadis_0entries.xrds', [])

    def test_success(self):
        self.failUnlessXRDSHasReturnURLs(
            'http://unittest/return_to.xrds',
            [
                'http://rp.example.com/return',
                'http://mirror.rp.example.com/return',
            ]
        )


class TestReturnToMatches(unittest.TestCase):
    def test_noEntries(self):
        self.assertFalse(trustroot.returnToMatches([], 'anything'))

    def test_exactMatch(self):
        r = 'http://example.com/return.to'
        self.assertTrue(trustroot.returnToMatches([r], r))

    def test_garbageMatch(self):
        r = 'http://example.com/return.to'
        self.assertTrue(trustroot.returnToMatches(
            ['This is not a URL at all. In fact, it has characters, '
             'like "<" that are not allowed in URLs',
             r],
            r))

    def test_descendant(self):
        r = 'http://example.com/return.to'
        self.assertTrue(trustroot.returnToMatches(
            [r],
            'http://example.com/return.to/user:joe'))

    def test_wildcard(self):
        self.assertFalse(trustroot.returnToMatches(
            ['http://*.example.com/return.to'],
            'http://example.com/return.to'))

    def test_noMatch(self):
        r = 'http://example.com/return.to'
        self.assertFalse(trustroot.returnToMatches(
            [r],
            'http://example.com/xss_exploit'))

class TestVerifyReturnTo(unittest.TestCase, CatchLogs):

    def setUp(self):
        CatchLogs.setUp(self)

    def tearDown(self):
        CatchLogs.tearDown(self)

    def test_bogusRealm(self):
        self.assertFalse(trustroot.verifyReturnTo('', 'http://example.com/'))

    def test_verifyWithDiscoveryCalled(self):
        realm = 'http://*.example.com/'
        return_to = 'http://www.example.com/foo'

        def vrfy(disco_url):
            self.assertEqual('http://www.example.com/', disco_url)
            return [return_to]

        self.assertTrue(
            trustroot.verifyReturnTo(realm, return_to, _vrfy=vrfy))
        self.failUnlessLogEmpty()

    def test_verifyFailWithDiscoveryCalled(self):
        realm = 'http://*.example.com/'
        return_to = 'http://www.example.com/foo'

        def vrfy(disco_url):
            self.assertEqual('http://www.example.com/', disco_url)
            return ['http://something-else.invalid/']

        self.assertFalse(
            trustroot.verifyReturnTo(realm, return_to, _vrfy=vrfy))
        self.failUnlessLogMatches("Failed to validate return_to")

    def test_verifyFailIfDiscoveryRedirects(self):
        realm = 'http://*.example.com/'
        return_to = 'http://www.example.com/foo'

        def vrfy(disco_url):
            raise trustroot.RealmVerificationRedirected(
                disco_url, "http://redirected.invalid")

        self.assertFalse(
            trustroot.verifyReturnTo(realm, return_to, _vrfy=vrfy))
        self.failUnlessLogMatches("Attempting to verify")

if __name__ == '__main__':
    unittest.main()
