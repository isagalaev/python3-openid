"""Tests for consumer handling of association responses

This duplicates some things that are covered by test_consumer, but
this works for now.
"""
from openid.test.test_consumer import CatchLogs
from openid.message import Message, OPENID2_NS, OPENID_NS
from openid.consumer import Consumer, ProtocolError
from openid.discover import Service, OPENID_1_1_TYPE,\
    OPENID_2_0_TYPE
from openid.store import memstore
import unittest

# Some values we can use for convenience (see mkAssocResponse)
association_response_values = {
    'expires_in': '1000',
    'assoc_handle': 'a handle',
    'assoc_type': 'a type',
    'session_type': 'a session type',
    'ns': OPENID2_NS,
}


def mkAssocResponse(*keys):
    """Build an association response message that contains the
    specified subset of keys. The values come from
    `association_response_values`.

    This is useful for testing for missing keys and other times that
    we don't care what the values are."""
    args = dict([(key, association_response_values[key]) for key in keys])
    return Message.fromOpenIDArgs(args)


class BaseAssocTest(CatchLogs, unittest.TestCase):
    def setUp(self):
        CatchLogs.setUp(self)
        self.store = memstore.MemoryStore()
        self.consumer = Consumer({}, self.store)
        self.endpoint = Service()

    def failUnlessProtocolError(self, str_prefix, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except ProtocolError as e:
            e_arg = e.args[0]
            message = 'Expected prefix %r, got %r' % (str_prefix, e_arg)
            self.assertTrue(e_arg.startswith(str_prefix), message)
        else:
            self.fail('Expected ProtocolError, got %r' % (result,))


def mkExtractAssocMissingTest(keys):
    """Factory function for creating test methods for generating
    missing field tests.

    Make a test that ensures that an association response that
    is missing required fields will short-circuit return None.

    According to 'Association Session Response' subsection 'Common
    Response Parameters', the following fields are required for OpenID
    2.0:

     * ns
     * session_type
     * assoc_handle
     * assoc_type
     * expires_in

    If 'ns' is missing, it will fall back to OpenID 1 checking. In
    OpenID 1, everything except 'session_type' and 'ns' are required.
    """

    def test(self):
        msg = mkAssocResponse(*keys)

        self.assertRaises(KeyError,
                              self.consumer._extractAssociation, msg, None)

    return test


class TestExtractAssociationMissingFieldsOpenID2(BaseAssocTest):
    """Test for returning an error upon missing fields in association
    responses for OpenID 2"""

    test_noFields_openid2 = mkExtractAssocMissingTest(['ns'])

    test_missingExpires_openid2 = mkExtractAssocMissingTest(
        ['assoc_handle', 'assoc_type', 'session_type', 'ns'])

    test_missingHandle_openid2 = mkExtractAssocMissingTest(
        ['expires_in', 'assoc_type', 'session_type', 'ns'])

    test_missingAssocType_openid2 = mkExtractAssocMissingTest(
        ['expires_in', 'assoc_handle', 'session_type', 'ns'])

    test_missingSessionType_openid2 = mkExtractAssocMissingTest(
        ['expires_in', 'assoc_handle', 'assoc_type', 'ns'])


class TestExtractAssociationMissingFieldsOpenID1(BaseAssocTest):
    """Test for returning an error upon missing fields in association
    responses for OpenID 2"""

    test_noFields_openid1 = mkExtractAssocMissingTest([])

    test_missingExpires_openid1 = mkExtractAssocMissingTest(
        ['assoc_handle', 'assoc_type'])

    test_missingHandle_openid1 = mkExtractAssocMissingTest(
        ['expires_in', 'assoc_type'])

    test_missingAssocType_openid1 = mkExtractAssocMissingTest(
        ['expires_in', 'assoc_handle'])


class DummyAssocationSession(object):
    def __init__(self, session_type, allowed_assoc_types=()):
        self.session_type = session_type
        self.allowed_assoc_types = allowed_assoc_types


class ExtractAssociationSessionTypeMismatch(BaseAssocTest):
    def mkTest(requested_session_type, response_session_type, openid1=False):
        def test(self):
            assoc_session = DummyAssocationSession(requested_session_type)
            keys = list(association_response_values.keys())
            if openid1:
                keys.remove('ns')
            msg = mkAssocResponse(*keys)
            msg.setArg(OPENID_NS, 'session_type', response_session_type)
            self.failUnlessProtocolError('Session type mismatch',
                self.consumer._extractAssociation, msg, assoc_session)

        return test

    test_typeMismatchNoEncBlank_openid2 = mkTest(
        requested_session_type='no-encryption',
        response_session_type='',
        )

    test_typeMismatchDHSHA1NoEnc_openid2 = mkTest(
        requested_session_type='DH-SHA1',
        response_session_type='no-encryption',
        )

    test_typeMismatchDHSHA256NoEnc_openid2 = mkTest(
        requested_session_type='DH-SHA256',
        response_session_type='no-encryption',
        )

    test_typeMismatchNoEncDHSHA1_openid2 = mkTest(
        requested_session_type='no-encryption',
        response_session_type='DH-SHA1',
        )

    test_typeMismatchDHSHA1NoEnc_openid1 = mkTest(
        requested_session_type='DH-SHA1',
        response_session_type='DH-SHA256',
        openid1=True,
        )

    test_typeMismatchDHSHA256NoEnc_openid1 = mkTest(
        requested_session_type='DH-SHA256',
        response_session_type='DH-SHA1',
        openid1=True,
        )

    test_typeMismatchNoEncDHSHA1_openid1 = mkTest(
        requested_session_type='no-encryption',
        response_session_type='DH-SHA1',
        openid1=True,
        )


class TestOpenID1AssociationResponseSessionType(BaseAssocTest):
    def mkTest(expected_session_type, session_type_value):
        """Return a test method that will check what session type will
        be used if the OpenID 1 response to an associate call sets the
        'session_type' field to `session_type_value`
        """
        def test(self):
            self._doTest(expected_session_type, session_type_value)
            self.assertEqual(0, len(self.messages))

        return test

    def _doTest(self, expected_session_type, session_type_value):
        # Create a Message with just 'session_type' in it, since
        # that's all this function will use. 'session_type' may be
        # absent if it's set to None.
        args = {}
        if session_type_value is not None:
            args['session_type'] = session_type_value
        message = Message.fromOpenIDArgs(args)
        self.assertTrue(message.isOpenID1())

        actual_session_type = self.consumer._getOpenID1SessionType(message)
        error_message = ('Returned sesion type parameter %r was expected '
                         'to yield session type %r, but yielded %r' %
                         (session_type_value, expected_session_type,
                          actual_session_type))
        self.assertEqual(
            expected_session_type, actual_session_type, error_message)

    test_none = mkTest(
        session_type_value=None,
        expected_session_type='no-encryption',
        )

    test_empty = mkTest(
        session_type_value='',
        expected_session_type='no-encryption',
        )

    # This one's different because it expects log messages
    def test_explicitNoEncryption(self):
        self._doTest(
            session_type_value='no-encryption',
            expected_session_type='no-encryption',
            )
        self.assertEqual(1, len(self.messages))
        log_msg = self.messages[0]
        self.assertEqual(log_msg['levelname'], 'WARNING')
        self.assertTrue(log_msg['msg'].startswith(
                'OpenID server sent "no-encryption"'))

    test_dhSHA1 = mkTest(
        session_type_value='DH-SHA1',
        expected_session_type='DH-SHA1',
        )

    # DH-SHA256 is not a valid session type for OpenID1, but this
    # function does not test that. This is mostly just to make sure
    # that it will pass-through stuff that is not explicitly handled,
    # so it will get handled the same way as it is handled for OpenID
    # 2
    test_dhSHA256 = mkTest(
        session_type_value='DH-SHA256',
        expected_session_type='DH-SHA256',
        )


class DummyAssociationSession(object):
    secret = b"shh! don't tell!"  # association secrets are bytes
    extract_secret_called = False

    session_type = None

    allowed_assoc_types = None

    def extractSecret(self, message):
        self.extract_secret_called = True
        return self.secret


class TestInvalidFields(BaseAssocTest):
    def setUp(self):
        BaseAssocTest.setUp(self)
        self.session_type = 'testing-session'

        # This must something that works for Association.fromExpiresIn
        self.assoc_type = 'HMAC-SHA1'

        self.assoc_handle = 'testing-assoc-handle'

        # These arguments should all be valid
        self.assoc_response = Message.fromOpenIDArgs({
            'expires_in': '1000',
            'assoc_handle': self.assoc_handle,
            'assoc_type': self.assoc_type,
            'session_type': self.session_type,
            'ns': OPENID2_NS,
            })

        self.assoc_session = DummyAssociationSession()

        # Make the session for the response's session type
        self.assoc_session.session_type = self.session_type
        self.assoc_session.allowed_assoc_types = [self.assoc_type]

    def test_worksWithGoodFields(self):
        """Handle a full successful association response"""
        assoc = self.consumer._extractAssociation(
            self.assoc_response, self.assoc_session)
        self.assertTrue(self.assoc_session.extract_secret_called)
        self.assertEqual(self.assoc_session.secret, assoc.secret)
        self.assertEqual(1000, assoc.lifetime)
        self.assertEqual(self.assoc_handle, assoc.handle)
        self.assertEqual(self.assoc_type, assoc.assoc_type)

    def test_badAssocType(self):
        # Make sure that the assoc type in the response is not valid
        # for the given session.
        self.assoc_session.allowed_assoc_types = []
        self.failUnlessProtocolError('Unsupported assoc_type for session',
            self.consumer._extractAssociation,
            self.assoc_response, self.assoc_session)

    def test_badExpiresIn(self):
        # Invalid value for expires_in should cause failure
        self.assoc_response.setArg(OPENID_NS, 'expires_in', 'forever')
        self.failUnlessProtocolError('Invalid expires_in',
            self.consumer._extractAssociation,
            self.assoc_response, self.assoc_session)


# XXX: This is what causes most of the imports in this file. It is
# sort of a unit test and sort of a functional test. I'm not terribly
# fond of it.
class TestExtractAssociationDiffieHellman(BaseAssocTest):
    secret = b'x' * 20

    def _setUpDH(self):
        sess, message = self.consumer._createAssociateRequest(
            self.endpoint, 'HMAC-SHA1', 'DH-SHA1')

        # XXX: this is testing _createAssociateRequest
        self.assertEqual(self.endpoint.compat_mode(),  message.isOpenID1())

        # Update to predicatable values, we don't need to test server implementation
        sess.dh.__dict__.update({
            'generator': 2,
            'modulus': 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443,
            'private': 126711330346638818413185314607323328440249044939093367341709697885270109252062150705850448574632531951284272220717033495463270445787160903870419502807949843952972401800260674036844375831162460893125215028686746173200343317756593951895946222096220729935912958283407058549768824948320551518281925780854490478757,
            'public': 61939986309620003692127009575126578837756635127190161758785900189836107480644504682970374032956588831023442047858856773401858972905564850232001765924840660429731688280767034223334320886143073515491698974349792422172901308097445194441607035980943036176812117975924682316467383068443084176904644018521558803791,
        })
        message.setArg(OPENID_NS, 'dh_consumer_public', 'WDSZk0kxTcD6Hak5H/7R/mEBMcE6YMmPN9kXHBWDtHhSGb35J6ud5nKy+Ug76sxukvmaUEBTK4nFl1UvVNx1m80IFGLNSLer28OzJ7f44RhUAqlmkwVJVTYOEwTVslLTU2BRCQz1zHj3MJeFgcdy5t/oLHYqcUtMCTALnFlo5U8=')
        server_resp = {
            'dh_server_public': b'AIw2FVT4ara9QNk55/QKkTx6xqbsr6YF8WQGgZdapd/+3V0y2UAUrcnOuueHPAnEo1XR/n+lnqwzW0MfbjchNodiscNkyGJDWpYRhKmCPAOpGpd11qXvSkCySrO6wETBddtPbosQOa1o/pnJ7xKx8/0aQ5a3cBJjtZVyLwQNzi+W',
            'enc_mac_key': b'iypdEVSuyrRYj3liUZdUtk7jrt0=',
            'assoc_type': 'HMAC-SHA1',
            'assoc_handle': 'handle',
            'expires_in': '1000',
            'session_type': 'DH-SHA1',
        }
        return sess, Message.fromOpenIDArgs(server_resp)

    def test_success(self):
        sess, server_resp = self._setUpDH()
        ret = self.consumer._extractAssociation(server_resp, sess)
        self.assertFalse(ret is None)
        self.assertEqual(ret.assoc_type, 'HMAC-SHA1')
        self.assertEqual(ret.secret, self.secret)
        self.assertEqual(ret.handle, 'handle')
        self.assertEqual(ret.lifetime, 1000)

    def test_openid2success(self):
        # Use openid 2 type in endpoint so _setUpDH checks
        # compatibility mode state properly
        self.endpoint.types = [OPENID_2_0_TYPE, OPENID_1_1_TYPE]
        self.test_success()

    def test_badDHValues(self):
        sess, server_resp = self._setUpDH()
        server_resp.setArg(OPENID_NS, 'enc_mac_key', '\x00\x00\x00')
        self.failUnlessProtocolError('Malformed response for',
            self.consumer._extractAssociation, server_resp, sess)
