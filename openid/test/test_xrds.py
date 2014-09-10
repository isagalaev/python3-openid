import unittest
import os.path

from openid import xrds, xri
from openid.yadis import services


def datapath(filename):
    module_directory = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_directory, 'data', 'test_xrds', filename)

XRD_FILE = datapath('valid-populated-xrds.xml')
NOXRDS_FILE = datapath('not-xrds.xml')
NOXRD_FILE = datapath('no-xrd.xml')

# None of the namespaces or service URIs below are official (or even
# sanctioned by the owners of that piece of URL-space)

LID_2_0 = "http://lid.netmesh.org/sso/2.0b5"
TYPEKEY_1_0 = "http://typekey.com/services/1.0"


def simpleOpenIDTransformer(uri, yadis_url, service_element):
    """Function to extract information from an OpenID service element"""
    if 'http://openid.net/signon/1.0' not in xrds.getTypeURIs(service_element):
        return None

    delegates = list(service_element.findall(
        '{http://openid.net/xmlns/1.0}Delegate'))
    assert len(delegates) == 1
    delegate = delegates[0].text
    return (uri, delegate)

def no_op_filter(*args):
    return args

class TestServiceParser(unittest.TestCase):
    def setUp(self):
        with open(XRD_FILE, 'rb') as f:
            self.xmldoc = f.read()
        self.yadis_url = 'http://unittest.url/'

    def _getServices(self, flt=no_op_filter):
        return list(services.applyFilter(self.yadis_url, self.xmldoc, flt))

    def testParse(self):
        """Make sure that parsing succeeds at all"""
        services = self._getServices()

    def testParseOpenID(self):
        """Parse for OpenID services with a transformer function"""
        services = self._getServices(simpleOpenIDTransformer)

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
            for uri, yadis_url, element in it:
                if type_uri in xrds.getTypeURIs(element):
                    self.assertEqual(uri, service_uri)
                    break
            else:
                self.fail('Did not find %r service' % (type_uri,))

    def testGetSeveral(self):
        """Get some services in order"""
        expectedServices = [
            # type, URL
            (TYPEKEY_1_0, None),
            (LID_2_0, "http://mylid.net/josh"),
            ]

        self._checkServices(expectedServices)

    def testGetSeveralForOne(self):
        """Getting services for one Service with several Type elements."""
        types = ['http://lid.netmesh.org/sso/2.0b5',
                 'http://lid.netmesh.org/2.0b5'
                ]

        reference_uri = "http://mylid.net/josh"

        for uri, yadis_url, element in self._getServices():
            if uri == reference_uri:
                found_types = xrds.getTypeURIs(element)
                if found_types == types:
                    break
        else:
            self.fail('Did not find service with expected types and uris')

    def testNoXRDS(self):
        """Make sure that we get an exception when an XRDS element is
        not present"""
        with open(NOXRDS_FILE, 'rb') as f:
            self.xmldoc = f.read()
        self.assertRaises(
            xrds.XRDSError,
            services.applyFilter, self.yadis_url, self.xmldoc, no_op_filter)

    def testEmpty(self):
        """Make sure that we get an exception when an XRDS element is
        not present"""
        self.xmldoc = ''
        self.assertRaises(
            xrds.XRDSError,
            services.applyFilter, self.yadis_url, self.xmldoc, no_op_filter)

    def testNoXRD(self):
        """Make sure that we get an exception when there is no XRD
        element present."""
        with open(NOXRD_FILE, 'rb') as f:
            self.xmldoc = f.read()
        self.assertRaises(
            xrds.XRDSError,
            services.applyFilter, self.yadis_url, self.xmldoc, no_op_filter)


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
