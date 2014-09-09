import unittest
from unittest import mock

from openid.yadis import services
from openid.yadis.discover import DiscoveryFailure

from . import support


@mock.patch('urllib.request.urlopen', support.urlopen)
class TestGetServiceEndpoints(unittest.TestCase):

    def test_catchXRDSError(self):
        self.assertRaises(DiscoveryFailure,
                              services.getServiceEndpoints,
                              'http://unittest/junk.txt')


if __name__ == '__main__':
    unittest.main()
