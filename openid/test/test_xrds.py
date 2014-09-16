import unittest
from unittest import mock
import os.path

from openid import fetchers, xrds
from . import support


def datapath(filename):
    module_directory = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_directory, 'data', 'test_xrds', filename)

# None of the namespaces or service URIs below are official (or even
# sanctioned by the owners of that piece of URL-space)

LID_2_0 = "http://lid.netmesh.org/sso/2.0b5"


def simple_constructor(service_element):
    delegates = list(service_element.findall(
        '{http://openid.net/xmlns/1.0}Delegate'))
    assert len(delegates) == 1
    delegate = delegates[0].text
    return (xrds.getURI(service_element), delegate)


@mock.patch('urllib.request.urlopen', support.urlopen)
class TestServiceParser(unittest.TestCase):
    def _getServices(self, types=[], constructor=lambda x: x):
        data = fetchers.fetch('http://unittest/test_xrds/valid-populated-xrds.xml').read()
        return [constructor(e) for e in xrds.get_elements(data, types)]

    def testParse(self):
        """Make sure that parsing succeeds at all"""
        services = self._getServices()

    def testParseOpenID(self):
        """Parse for OpenID services with a transformer function"""
        services = self._getServices(['http://openid.net/signon/1.0'], simple_constructor)

        expectedServices = [
            ("http://www.myopenid.com/server", "http://josh.myopenid.com/"),
            ("http://www.schtuff.com/openid", "http://users.schtuff.com/josh"),
            ("http://www.livejournal.com/openid/server.bml",
             "http://www.livejournal.com/users/nedthealpaca/"),
            ]

        it = iter(services)
        for (server_url, delegate) in expectedServices:
            for (actual_url, actual_delegate) in it:
                self.assertEqual(server_url, actual_url)
                self.assertEqual(delegate, actual_delegate)
                break
            else:
                self.fail('Not enough services found')

    def _checkServices(self, expectedServices):
        """Check to make sure that the expected services are found in
        that order in the parsed document."""
        it = iter(self._getServices())
        for (type_uri, service_uri) in expectedServices:
            for element in it:
                if type_uri in xrds.getTypeURIs(element):
                    self.assertEqual(xrds.getURI(element), service_uri)
                    break
            else:
                self.fail('Did not find %r service' % (type_uri,))

    def testGetSeveral(self):
        """Get some services in order"""
        expectedServices = [
            # type, URL
            (LID_2_0, "http://mylid.net/josh"),
            ]

        self._checkServices(expectedServices)

    def testGetSeveralForOne(self):
        """Getting services for one Service with several Type elements."""
        types = ['http://lid.netmesh.org/sso/2.0b5',
                 'http://lid.netmesh.org/2.0b5'
                ]

        reference_uri = "http://mylid.net/josh"

        for element in self._getServices():
            if xrds.getURI(element) == reference_uri and \
               xrds.getTypeURIs(element) == types:
                break
        else:
            self.fail('Did not find service with expected types and uris')

    def testNoXRDS(self):
        data = fetchers.fetch('http://unittest/test_xrds/not-xrds.xml').read()
        self.assertRaises(
            xrds.XRDSError,
            xrds.get_elements, data, [])

    def testNoXRD(self):
        data = fetchers.fetch('http://unittest/test_xrds/no-xrd.xml').read()
        self.assertRaises(
            xrds.XRDSError,
            xrds.get_elements, data, [])

    def testMultipleXRD(self):
        data = fetchers.fetch('http://unittest/test_xrds/multiple-xrd.xml').read()
        elements = xrds.get_elements(data, [])
        self.assertEqual(len(elements), 2)

    def testEmpty(self):
        """Make sure that we get an exception when an XRDS element is
        not present"""
        data = fetchers.fetch('http://unittest/200.txt').read()
        self.assertRaises(
            xrds.XRDSError,
            xrds.get_elements, data, [])


@mock.patch('urllib.request.urlopen', support.urlopen)
class LocalID(unittest.TestCase):
    def _get_service(self, url):
        data = fetchers.fetch(url).read()
        return xrds.iterServices(xrds.parseXRDS(data))[0]

    def test_success(self):
        local_id = 'http://smoker.myopenid.com/'
        element = self._get_service('http://unittest/openid_1_and_2_xrds.xrds')
        self.assertEqual(xrds.getLocalID(element, True, False), local_id)
        self.assertEqual(xrds.getLocalID(element, False, True), local_id)

    def test_no_local_id(self):
        element = self._get_service('http://unittest/openid2_xrds_no_local_id.xrds')
        self.assertIsNone(xrds.getLocalID(element, True, False))
        self.assertIsNone(xrds.getLocalID(element, False, True))

    def test_mismatch(self):
        data = fetchers.fetch('http://unittest/openid_1_and_2_xrds_bad_delegate.xrds').read()
        element = xrds.iterServices(xrds.parseXRDS(data))[0]
        with self.assertRaises(xrds.XRDSError):
            xrds.getLocalID(element, True, True)


@support.gentests
class CanonicalID(unittest.TestCase):
    data = [
        ('delegated', ("@ootao*test1", "delegated-20060809.xrds", "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")),
        ('delegated_r1', ("@ootao*test1", "delegated-20060809-r1.xrds", "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")),
        ('delegated_r2', ("@ootao*test1", "delegated-20060809-r2.xrds", "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")),
        ('sometimesprefix', ("@ootao*test1", "sometimesprefix.xrds", "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")),
        ('prefixsometimes', ("@ootao*test1", "prefixsometimes.xrds", "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")),
        ('spoof1', ("=keturn*isDrummond", "spoof1.xrds", xrds.XRDSFraud)),
        ('spoof2', ("=keturn*isDrummond", "spoof2.xrds", xrds.XRDSFraud)),
        ('spoof3', ("@keturn*is*drummond", "spoof3.xrds", xrds.XRDSFraud)),
        ('status222', ("=x", "status222.xrds", None)),
        ('multisegment_xri', ('xri://=nishitani*masaki', 'subsegments.xrds', '=!E117.EF2F.454B.C707!0000.0000.3B9A.CA01')),
        ('iri_auth_not_allowed', ("phreak.example.com", "delegated-20060809-r2.xrds", xrds.XRDSFraud)),
    ]

    def _test(self, iname, filename, expectedID):
        with open(datapath(filename), 'rb') as f:
            et = xrds.parseXRDS(f.read())
        if expectedID is xrds.XRDSFraud:
            self.assertRaises(expectedID, xrds.getCanonicalID, iname, et)
        else:
            cid = xrds.getCanonicalID(iname, et)
            self.assertEqual(cid, expectedID)


if __name__ == '__main__':
    unittest.main()
