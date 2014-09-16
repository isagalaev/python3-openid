import unittest
from unittest import mock
import os.path

from openid import fetchers, xrds, xri
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


class TestCanonicalID(unittest.TestCase):

    def mkTest(iname, filename, expectedID):
        """This function builds a method that runs the CanonicalID
        test for the given set of inputs"""

        filename = datapath(filename)

        def test(self):
            with open(filename, 'rb') as f:
                et = xrds.parseXRDS(f.read())
            self._getCanonicalID(iname, et, expectedID)
        return test

    test_delegated = mkTest(
        "@ootao*test1", "delegated-20060809.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_delegated_r1 = mkTest(
        "@ootao*test1", "delegated-20060809-r1.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_delegated_r2 = mkTest(
        "@ootao*test1", "delegated-20060809-r2.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_sometimesprefix = mkTest(
        "@ootao*test1", "sometimesprefix.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_prefixsometimes = mkTest(
        "@ootao*test1", "prefixsometimes.xrds",
        "@!5BAD.2AA.3C72.AF46!0000.0000.3B9A.CA01")

    test_spoof1 = mkTest("=keturn*isDrummond", "spoof1.xrds", xrds.XRDSFraud)

    test_spoof2 = mkTest("=keturn*isDrummond", "spoof2.xrds", xrds.XRDSFraud)

    test_spoof3 = mkTest("@keturn*is*drummond", "spoof3.xrds", xrds.XRDSFraud)

    test_status222 = mkTest("=x", "status222.xrds", None)

    test_multisegment_xri = mkTest('xri://=nishitani*masaki',
                                   'subsegments.xrds',
                                   '=!E117.EF2F.454B.C707!0000.0000.3B9A.CA01')

    test_iri_auth_not_allowed = mkTest(
        "phreak.example.com", "delegated-20060809-r2.xrds", xrds.XRDSFraud)
    test_iri_auth_not_allowed.__doc__ = \
        "Don't let IRI authorities be canonical for the GCS."

    # TODO: Refs
    # test_ref = mkTest("@ootao*test.ref", "ref.xrds", "@!BAE.A650.823B.2475")

    # TODO: Add a IRI authority with an IRI canonicalID.
    # TODO: Add test cases with real examples of multiple CanonicalIDs
    #   somewhere in the resolution chain.

    def _getCanonicalID(self, iname, et, expectedID):
        if isinstance(expectedID, (str, type(None))):
            cid = xrds.getCanonicalID(iname, et)
            self.assertEqual(cid, expectedID and xri.XRI(expectedID))
        elif issubclass(expectedID, xrds.XRDSError):
            self.assertRaises(expectedID, xrds.getCanonicalID,
                                  iname, et)
        else:
            self.fail("Don't know how to test for expected value %r"
                      % (expectedID,))


if __name__ == '__main__':
    unittest.main()
