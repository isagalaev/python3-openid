import unittest

from openid.yadis import services, etxrd
from openid.yadis.discover import DiscoveryFailure


class TestGetServiceEndpoints(unittest.TestCase):
    def setUp(self):
        self.orig_discover = services.discover
        services.discover = self.discover

    def tearDown(self):
        services.discover = self.orig_discover

    def discover(self, input_url):
        return etxrd.parseXRDS('This is not XRDS text.')

    def test_catchXRDSError(self):
        self.assertRaises(DiscoveryFailure,
                              services.getServiceEndpoints,
                              "http://example.invalid/sometest")


if __name__ == '__main__':
    unittest.main()
