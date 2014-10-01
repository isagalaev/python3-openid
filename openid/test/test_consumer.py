import urllib.parse
import urllib.error
import time
import warnings
import pprint
from unittest import mock
import io

from openid.message import Message, OPENID_NS, OPENID2_NS, IDENTIFIER_SELECT, \
     OPENID1_NS, BARE_NS
from openid import cryptutil, oidutil, kvform
from openid.store.nonce import mkNonce, split as splitNonce
from openid.consumer.discover import Service, OPENID_2_0_TYPE, \
     OPENID_1_1_TYPE, OPENID_1_0_TYPE, OPENID_IDP_2_0_TYPE, DiscoveryFailure
from openid.consumer.consumer import \
     AuthRequest, GenericConsumer, \
     SuccessResponse, SetupNeededResponse, CancelResponse, \
     DiffieHellmanSHA1ConsumerSession, Consumer, PlainTextConsumerSession, \
     DiffieHellmanSHA256ConsumerSession, ServerError, \
     ProtocolError, makeKVPost, NONCE_ARG, VerificationError
from openid import association
from openid.server.server import \
     PlainTextServerSession, DiffieHellmanSHA1ServerSession
from openid.dh import DiffieHellman
from openid import fetchers
from openid.store import memstore
from openid.extension import Extension

from . import support
from .support import CatchLogs, HTTPResponse


assocs = [
    ('another 20-byte key.', 'Snarky'),
    ('\x00' * 20, 'Zeros'),
    ]


def mkSuccess(endpoint, q):
    """Convenience function to create a SuccessResponse with the given
    arguments, all signed."""
    signed_list = ['openid.' + k for k in list(q.keys())]
    return SuccessResponse(endpoint, Message.fromOpenIDArgs(q), signed_list)

def parseQuery(qs):
    q = {}
    for (k, v) in urllib.parse.parse_qsl(qs):
        assert k not in q
        q[k] = v
    return q


def associate(qs, assoc_secret, assoc_handle):
    """Do the server's half of the associate call, using the given
    secret and handle."""
    q = parseQuery(qs)
    assert q['openid.mode'] == 'associate'
    assert q['openid.assoc_type'] == 'HMAC-SHA1'
    reply_dict = {
        'assoc_type': 'HMAC-SHA1',
        'assoc_handle': assoc_handle,
        'expires_in': '600',
        }

    if q.get('openid.session_type') == 'DH-SHA1':
        assert len(q) == 6 or len(q) == 4
        message = Message.fromPostArgs(q)
        session = DiffieHellmanSHA1ServerSession.fromMessage(message)
        reply_dict['session_type'] = 'DH-SHA1'
    else:
        assert len(q) == 2
        session = PlainTextServerSession.fromQuery(q)

    reply_dict.update(session.answer(assoc_secret))
    return kvform.dictToKV(reply_dict)


GOODSIG = "[A Good Signature]"


class GoodAssociation:
    expiresIn = 3600
    handle = "-blah-"

    def checkMessageSignature(self, message):
        return message.getArg(OPENID_NS, 'sig') == GOODSIG


class GoodAssocStore(memstore.MemoryStore):
    def getAssociation(self, server_url, handle=None):
        return GoodAssociation()


def _nsdict(data):
    default = {'openid.ns': OPENID2_NS}
    default.update(data)
    return default


class TestFetcher(object):
    def __init__(self, user_url, user_page, xxx_todo_changeme):
        (assoc_secret, assoc_handle) = xxx_todo_changeme
        self.get_responses = {
            user_url: user_page
        }
        self.assoc_secret = assoc_secret
        self.assoc_handle = assoc_handle
        self.num_assocs = 0

    def fetch(self, url, body=None, headers=None):
        if body is None:
            if url in self.get_responses:
                return HTTPResponse(url, 200, body=self.get_responses[url])
        else:
            try:
                body.index('openid.mode=associate')
            except ValueError:
                pass  # fall through
            else:
                assert body.find('DH-SHA1') != -1
                response = associate(
                    body, self.assoc_secret, self.assoc_handle)
                self.num_assocs += 1
                return HTTPResponse(url, 200, body=response)

        raise urllib.error.HTTPError(url, 404, '', {}, io.BytesIO(b'Not found'))


def create_session(type):
    """
    Create custom DH object so tests run quickly.
    """
    assert type == 'DH-SHA1'
    dh = DiffieHellman(100389557, 2)
    return DiffieHellmanSHA1ConsumerSession(dh)


def _test_success(server_url, user_url, delegate_url, links, immediate=False):
    if isinstance(server_url, bytes):
        server_url = str(server_url, encoding="utf-8")
    if isinstance(user_url, bytes):
        user_url = str(user_url, encoding="utf-8")
    if isinstance(delegate_url, bytes):
        delegate_url = str(delegate_url, encoding="utf-8")
    if isinstance(links, bytes):
        links = str(links, encoding="utf-8")

    store = memstore.MemoryStore()
    if immediate:
        mode = 'checkid_immediate'
    else:
        mode = 'checkid_setup'

    endpoint = Service([OPENID_1_1_TYPE], server_url, user_url, delegate_url)
    fetcher = TestFetcher(None, None, assocs[0])

    @mock.patch('openid.consumer.consumer.create_session', create_session)
    def run():
        trust_root = str(consumer_url, encoding="utf-8")

        consumer = Consumer({}, store)
        generic_consumer = consumer.consumer

        request = consumer.beginWithoutDiscovery(endpoint)
        return_to = str(consumer_url, encoding="utf-8")

        m = request.getMessage(trust_root, return_to, immediate)

        redirect_url = request.redirectURL(trust_root, return_to, immediate)
        if isinstance(redirect_url, bytes):
            redirect_url = str(redirect_url, encoding="utf-8")

        parsed = urllib.parse.urlparse(redirect_url)
        qs = parsed[4]
        q = parseQuery(qs)
        new_return_to = q['openid.return_to']
        del q['openid.return_to']
        expected = {
            'openid.mode': mode,
            'openid.identity': delegate_url,
            'openid.trust_root': trust_root,
            'openid.assoc_handle': fetcher.assoc_handle,
        }
        assert q == expected, pprint.pformat((q, expected))

        # (q, user_url, delegate_url, mode, expected)

        assert new_return_to.startswith(return_to)
        assert redirect_url.startswith(server_url)

        parsed = urllib.parse.urlparse(new_return_to)
        query = parseQuery(parsed[4])
        query.update({
            'openid.mode': 'id_res',
            'openid.return_to': new_return_to,
            'openid.identity': delegate_url,
            'openid.assoc_handle': fetcher.assoc_handle,
        })

        assoc = store.getAssociation(server_url, fetcher.assoc_handle)

        message = Message.fromPostArgs(query)
        message = assoc.signMessage(message)
        info = consumer._complete_id_res(message, request.endpoint, new_return_to)
        assert info.status == 'success', info.message
        assert info.identity() == user_url

    with mock.patch('openid.fetchers.fetch', fetcher.fetch):
        assert fetcher.num_assocs == 0
        run()
        assert fetcher.num_assocs == 1

        # Test that doing it again uses the existing association
        run()
        assert fetcher.num_assocs == 1

        # Another association is created if we remove the existing one
        store.removeAssociation(server_url, fetcher.assoc_handle)
        run()
        assert fetcher.num_assocs == 2

        # Test that doing it again uses the existing association
        run()
        assert fetcher.num_assocs == 2

import unittest

http_server_url = b'http://server.example.com/'
consumer_url = b'http://consumer.example.com/'
https_server_url = b'https://server.example.com/'


class TestSuccess(unittest.TestCase, CatchLogs):
    server_url = http_server_url
    user_url = b'http://www.example.com/user.html'
    delegate_url = b'http://consumer.example.com/user'

    def setUp(self):
        CatchLogs.setUp(self)
        self.links = '<link rel="openid.server" href="%s" />' % (
            self.server_url,)

        self.delegate_links = ('<link rel="openid.server" href="%s" />'
                               '<link rel="openid.delegate" href="%s" />') % (
            self.server_url, self.delegate_url)

    def tearDown(self):
        CatchLogs.tearDown(self)

    def test_nodelegate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links)

    def test_nodelegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.user_url, self.links, True)

    def test_delegate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links)

    def test_delegateImmediate(self):
        _test_success(self.server_url, self.user_url,
                      self.delegate_url, self.delegate_links, True)


class TestSuccessHTTPS(TestSuccess):
    server_url = https_server_url


class TestConstruct(unittest.TestCase):
    def setUp(self):
        self.store_sentinel = object()

    def test_construct(self):
        oidc = GenericConsumer(self.store_sentinel)
        self.assertTrue(oidc.store is self.store_sentinel)

    def test_nostore(self):
        self.assertRaises(TypeError, GenericConsumer)


class TestIdRes(unittest.TestCase, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)

        self.store = memstore.MemoryStore()
        self.new_consumer = Consumer({}, self.store)
        self.consumer = self.new_consumer.consumer
        self.return_to = 'http://unittest/complete'
        self.consumer_id = "consu"
        self.server_url = "serlie"
        self.server_id = "sirod"
        self.endpoint = Service([OPENID_1_1_TYPE], self.server_url, self.consumer_id, self.server_id)
        self.new_consumer.session[self.new_consumer._token_key] = self.endpoint

class TestIdResCheckSignature(TestIdRes):
    def setUp(self):
        TestIdRes.setUp(self)
        self.assoc = GoodAssociation()
        self.assoc.handle = "{not_dumb}"
        self.store.storeAssociation(self.endpoint.server_url, self.assoc)

        self.message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.identity': '=example',
            'openid.sig': GOODSIG,
            'openid.assoc_handle': self.assoc.handle,
            'openid.signed': 'mode,identity,assoc_handle,signed',
            'frobboz': 'banzit',
            })

    def test_sign(self):
        # assoc_handle to assoc with good sig
        self.new_consumer._idResCheckSignature(self.message,
                                           self.endpoint.server_url)

    def test_signFailsWithBadSig(self):
        self.message.setArg(OPENID_NS, 'sig', 'BAD SIGNATURE')
        self.assertRaises(
            VerificationError, self.new_consumer._idResCheckSignature,
            self.message, self.endpoint.server_url)

    @mock.patch('openid.consumer.consumer.makeKVPost', lambda *args: {})
    def test_stateless(self):
        # assoc_handle missing assoc, consumer._checkAuth returns goodthings
        self.message.setArg(OPENID_NS, "assoc_handle", "dumbHandle")
        self.consumer._processCheckAuthResponse = (
            lambda response, server_url: True)
        self.new_consumer._idResCheckSignature(self.message,
                                           self.endpoint.server_url)

    def test_statelessRaisesError(self):
        # assoc_handle missing assoc, consumer._checkAuth returns goodthings
        self.message.setArg(OPENID_NS, "assoc_handle", "dumbHandle")
        self.consumer._checkAuth = lambda unused1, unused2: False
        self.assertRaises(
            VerificationError, self.new_consumer._idResCheckSignature,
            self.message, self.endpoint.server_url)

    @mock.patch('openid.consumer.consumer.makeKVPost', lambda *args: {})
    def test_stateless_noStore(self):
        # assoc_handle missing assoc, consumer._checkAuth returns goodthings
        self.message.setArg(OPENID_NS, "assoc_handle", "dumbHandle")
        self.consumer.store = None
        self.consumer._processCheckAuthResponse = (
            lambda response, server_url: True)
        self.new_consumer._idResCheckSignature(self.message,
                                           self.endpoint.server_url)

    def test_statelessRaisesError_noStore(self):
        # assoc_handle missing assoc, consumer._checkAuth returns goodthings
        self.message.setArg(OPENID_NS, "assoc_handle", "dumbHandle")
        self.consumer._checkAuth = lambda unused1, unused2: False
        self.consumer.store = None
        self.assertRaises(
            VerificationError, self.new_consumer._idResCheckSignature,
            self.message, self.endpoint.server_url)


class TestQueryFormat(TestIdRes):
    def test_notAList(self):
        # XXX: should be a Message object test, not a consumer test

        # Value should be a single string.  If it's a list, it should generate
        # an exception.
        query = {'openid.mode': ['cancel']}
        try:
            r = Message.fromPostArgs(query)
        except TypeError as err:
            self.assertTrue(str(err).find('values') != -1, err)
        else:
            self.fail("expected TypeError, got this instead: %s" % (r,))


class Complete(unittest.TestCase):
    def setUp(self):
        self.consumer = Consumer({}, memstore.MemoryStore())
        self.claimed_id = 'claimed_id'
        service = Service(
            [OPENID_2_0_TYPE], 'http://unittest/server',
            self.claimed_id, self.claimed_id
        )
        self.consumer.session[self.consumer._token_key] = service
        self.return_to = 'http://unittest/complete'

    def test_id_res_setup_needed(self):
        query = _nsdict({'openid.mode': 'id_res'})
        setup_url = 'http://unittest/setup'
        with mock.patch.object(Message, 'setup_url') as m:
            m.return_value = setup_url
            response = self.consumer.complete(query, self.return_to)
        self.assertEqual('setup_needed', response.status)
        self.assertEqual(response.setup_url, setup_url)

    def test_cancel(self):
        query = _nsdict({'openid.mode': 'cancel'})
        response = self.consumer.complete(query, self.return_to)
        self.assertEqual(response.status, 'cancel')
        self.assertEqual(response.identity(), self.claimed_id)

    def test_error(self):
        query = _nsdict({
            'openid.mode': 'error',
            'openid.error': 'failed',
            'openid.contact': 'contact',
        })
        with self.assertRaises(VerificationError) as cm:
            self.consumer.complete(query, self.return_to)
        self.assertEqual(cm.exception.args[0], 'failed')
        self.assertEqual(cm.exception.response.getArg(OPENID2_NS, 'contact'), 'contact')

    def test_missing_field(self):
        query = _nsdict({'openid.mode': 'id_res'})
        self.assertRaises(VerificationError,
            self.consumer.complete, query, self.return_to
        )

    def test_no_mode(self):
        self.assertRaises(VerificationError,
            self.consumer.complete, {}, self.return_to
        )


class TestCompleteMissingSig(unittest.TestCase):
    def setUp(self):
        self.store = GoodAssocStore()
        self.consumer = Consumer({}, self.store)
        self.server_url = "http://idp.unittest/"
        self.return_to = 'http://unittest/complete'

        claimed_id = 'bogus.claimed'

        self.query = _nsdict({
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to,
            'openid.identity': claimed_id,
            'openid.assoc_handle': 'does not matter',
            'openid.sig': GOODSIG,
            'openid.response_nonce': mkNonce(),
            'openid.signed': 'identity,return_to,response_nonce,assoc_handle,claimed_id,op_endpoint',
            'openid.claimed_id': claimed_id,
            'openid.op_endpoint': self.server_url,
        })

        self.endpoint = Service([OPENID_2_0_TYPE], self.server_url, claimed_id)
        self.consumer.session[self.consumer._token_key] = self.endpoint

    def test_idResMissingNoSigs(self):
        r = self.consumer.complete(self.query, self.return_to)
        self.assertEqual(r.status, 'success')

    def test_idResNoIdentity(self):
        del self.query['openid.identity']
        del self.query['openid.claimed_id']
        self.endpoint.claimed_id = None
        self.query['openid.signed'] = 'return_to,response_nonce,assoc_handle,op_endpoint'
        r = self.consumer.complete(self.query, self.return_to)
        self.assertEqual(r.status, 'success')

    def test_idResMissingIdentitySig(self):
        self.query['openid.signed'] = 'return_to,response_nonce,assoc_handle,claimed_id'
        self.assertRaises(VerificationError,
            self.consumer.complete, self.query, self.return_to
        )

    def test_idResMissingReturnToSig(self):
        self.query['openid.signed'] = 'identity,response_nonce,assoc_handle,claimed_id'
        self.assertRaises(VerificationError,
            self.consumer.complete, self.query, self.return_to
        )

    def test_idResMissingAssocHandleSig(self):
        self.query['openid.signed'] = 'identity,response_nonce,return_to,claimed_id'
        self.assertRaises(VerificationError,
            self.consumer.complete, self.query, self.return_to
        )

    def test_idResMissingClaimedIDSig(self):
        self.query['openid.signed'] = 'identity,response_nonce,return_to,assoc_handle'
        self.assertRaises(VerificationError,
            self.consumer.complete, self.query, self.return_to
        )


class TestCheckAuthResponse(TestIdRes, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)
        TestIdRes.setUp(self)

    def tearDown(self):
        CatchLogs.tearDown(self)

    def _createAssoc(self):
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        store = self.consumer.store
        store.storeAssociation(self.server_url, assoc)
        assoc2 = store.getAssociation(self.server_url)
        self.assertEqual(assoc, assoc2)

    def test_goodResponse(self):
        """successful response to check_authentication"""
        response = Message.fromOpenIDArgs({'is_valid': 'true'})
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertTrue(r)

    def test_missingAnswer(self):
        """check_authentication returns false when server sends no answer"""
        response = Message.fromOpenIDArgs({})
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertFalse(r)

    def test_badResponse(self):
        """check_authentication returns false when is_valid is false"""
        response = Message.fromOpenIDArgs({'is_valid': 'false'})
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertFalse(r)

    def test_badResponseInvalidate(self):
        """Make sure that the handle is invalidated when is_valid is false

        From "Verifying directly with the OpenID Provider"::

            If the OP responds with "is_valid" set to "true", and
            "invalidate_handle" is present, the Relying Party SHOULD
            NOT send further authentication requests with that handle.
        """
        self._createAssoc()
        response = Message.fromOpenIDArgs({
            'is_valid': 'false',
            'invalidate_handle': 'handle',
            })
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertFalse(r)
        self.assertTrue(
            self.consumer.store.getAssociation(self.server_url) is None)

    def test_invalidateMissing(self):
        """invalidate_handle with a handle that is not present"""
        response = Message.fromOpenIDArgs({
            'is_valid': 'true',
            'invalidate_handle': 'missing',
            })
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertTrue(r)
        self.failUnlessLogMatches(
            'Received "invalidate_handle"'
            )

    def test_invalidateMissing_noStore(self):
        """invalidate_handle with a handle that is not present"""
        response = Message.fromOpenIDArgs({
            'is_valid': 'true',
            'invalidate_handle': 'missing',
            })
        self.consumer.store = None
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertTrue(r)
        self.failUnlessLogMatches(
            'Received "invalidate_handle"',
            'Unexpectedly got invalidate_handle without a store')

    def test_invalidatePresent(self):
        """invalidate_handle with a handle that exists

        From "Verifying directly with the OpenID Provider"::

            If the OP responds with "is_valid" set to "true", and
            "invalidate_handle" is present, the Relying Party SHOULD
            NOT send further authentication requests with that handle.
        """
        self._createAssoc()
        response = Message.fromOpenIDArgs({
            'is_valid': 'true',
            'invalidate_handle': 'handle',
            })
        r = self.consumer._processCheckAuthResponse(response, self.server_url)
        self.assertTrue(r)
        self.assertTrue(
            self.consumer.store.getAssociation(self.server_url) is None)


class TestSetupNeeded(TestIdRes):
    def failUnlessSetupNeeded(self, expected_setup_url, message):
        setup_url = message.setup_url()
        self.assertEqual(expected_setup_url, setup_url)

    def test_setupNeededOpenID1(self):
        """The minimum conditions necessary to trigger Setup Needed"""
        setup_url = 'http://unittest/setup-here'
        message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            })
        self.assertTrue(message.isOpenID1())
        self.failUnlessSetupNeeded(setup_url, message)

    def test_setupNeededOpenID1_extra(self):
        """Extra stuff along with setup_url still trigger Setup Needed"""
        setup_url = 'http://unittest/setup-here'
        message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.user_setup_url': setup_url,
            'openid.identity': 'bogus',
            })
        self.assertTrue(message.isOpenID1())
        self.failUnlessSetupNeeded(setup_url, message)

    def test_noSetupNeededOpenID1(self):
        """When the user_setup_url is missing on an OpenID 1 message,
        we assume that it's not a cancel response to checkid_immediate"""
        message = Message.fromOpenIDArgs({'mode': 'id_res'})
        self.assertTrue(message.isOpenID1())
        self.assertIsNone(message.setup_url())

    def test_setupNeededOpenID2(self):
        query = _nsdict({'openid.mode': 'setup_needed'})
        response = self.new_consumer.complete(query, None)
        self.assertEqual('setup_needed', response.status)
        self.assertEqual(None, response.setup_url)

    def test_setupNeededDoesntWorkForOpenID1(self):
        query = {'openid.mode': 'setup_needed'}
        self.assertIsNone(Message.fromPostArgs(query).setup_url())
        self.assertRaisesRegex(
            VerificationError, '^Invalid mode',
            self.new_consumer.complete, query, None,
        )

    def test_noSetupNeededOpenID2(self):
        message = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'game': 'puerto_rico',
            'ns': OPENID2_NS,
            })
        self.assertTrue(message.isOpenID2())
        self.assertIsNone(message.setup_url())


class FieldValidation(unittest.TestCase):

    def mkSuccessTest(openid_args, signed_list):
        def test(self):
            message = Message.fromOpenIDArgs(openid_args)
            message.setArg(OPENID_NS, 'signed', ','.join(signed_list))
            self.assertFalse(message.validate_fields())
        return test

    test_openid1Success = mkSuccessTest(
        {'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'identity': 'someone',
         },
        ['return_to', 'identity'])

    test_openid2Success = mkSuccessTest(
        {'ns': OPENID2_NS,
         'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'op_endpoint': 'my favourite server',
         'response_nonce': 'use only once',
         },
        ['return_to', 'response_nonce', 'assoc_handle', 'op_endpoint'])

    test_openid2Success_identifiers = mkSuccessTest(
        {'ns': OPENID2_NS,
         'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a siggnature',
         'claimed_id': 'i claim to be me',
         'identity': 'my server knows me as me',
         'op_endpoint': 'my favourite server',
         'response_nonce': 'use only once',
         },
        ['return_to', 'response_nonce', 'identity',
         'claimed_id', 'assoc_handle', 'op_endpoint'])

    def mkValidationTest(openid_args):
        def test(self):
            message = Message.fromOpenIDArgs(openid_args)
            self.assertTrue(message.validate_fields())
        return test

    test_openid1Missing_returnToSig = mkValidationTest(
        {'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'identity': 'someone',
         'signed': 'identity',
         })

    test_openid1Missing_identitySig = mkValidationTest(
        {'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'identity': 'someone',
         'signed': 'return_to'
         })

    test_openid2Missing_opEndpointSig = mkValidationTest(
        {'ns': OPENID2_NS,
         'return_to': 'return',
         'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'identity': 'someone',
         'op_endpoint': 'the endpoint',
         'signed': 'return_to,identity,assoc_handle'
         })

    test_openid1MissingReturnTo = mkValidationTest(
        {'assoc_handle': 'assoc handle',
         'sig': 'a signature',
         'identity': 'someone',
         })

    test_openid1MissingAssocHandle = mkValidationTest(
        {'return_to': 'return',
         'sig': 'a signature',
         'identity': 'someone',
         })

    # XXX: I could go on...


class CheckAuthHappened(Exception):
    pass


class CheckNonceVerifyTest(TestIdRes, CatchLogs):
    def setUp(self):
        CatchLogs.setUp(self)
        TestIdRes.setUp(self)

    def tearDown(self):
        CatchLogs.tearDown(self)

    def test_openid1Success(self):
        """use consumer-generated nonce"""
        nonce_value = mkNonce()

        query = urllib.parse.urlencode({NONCE_ARG: nonce_value})
        self.return_to = 'http://rt.unittest/?' + query
        self.response = Message.fromOpenIDArgs({'return_to': self.return_to})
        self.response.setArg(BARE_NS, NONCE_ARG, nonce_value)
        self.new_consumer._idResCheckNonce(self.response, self.endpoint)
        self.failUnlessLogEmpty()

    def test_consumerNonceOpenID2(self):
        """OpenID 2 does not use consumer-generated nonce"""
        self.return_to = 'http://rt.unittest/?nonce=%s' % (mkNonce(),)
        self.response = Message.fromOpenIDArgs(
            {'return_to': self.return_to, 'ns': OPENID2_NS})
        self.assertRaises(VerificationError,
            self.new_consumer._idResCheckNonce, self.response, self.endpoint
        )
        self.failUnlessLogEmpty()

    def test_serverNonce(self):
        """use server-generated nonce"""
        self.response = Message.fromOpenIDArgs(
            {'ns': OPENID2_NS, 'response_nonce': mkNonce()})
        self.new_consumer._idResCheckNonce(self.response, self.endpoint)
        self.failUnlessLogEmpty()

    def test_serverNonceOpenID1(self):
        """OpenID 1 does not use server-generated nonce"""
        self.response = Message.fromOpenIDArgs(
            {'ns': OPENID1_NS,
             'return_to': 'http://return.to/',
             'response_nonce': mkNonce()})
        self.assertRaises(VerificationError,
            self.new_consumer._idResCheckNonce, self.response, self.endpoint
        )
        self.failUnlessLogEmpty()

    def test_badNonce(self):
        """remove the nonce from the store

        From "Checking the Nonce"::

            When the Relying Party checks the signature on an assertion, the

            Relying Party SHOULD ensure that an assertion has not yet
            been accepted with the same value for "openid.response_nonce"
            from the same OP Endpoint URL.
        """
        nonce = mkNonce()
        stamp, salt = splitNonce(nonce)
        self.store.useNonce(self.server_url, stamp, salt)
        self.response = Message.fromOpenIDArgs(
                                  {'response_nonce': nonce,
                                   'ns': OPENID2_NS,
                                   })
        self.assertRaises(VerificationError,
            self.new_consumer._idResCheckNonce, self.response, self.endpoint
        )

    def test_successWithNoStore(self):
        """When there is no store, checking the nonce succeeds"""
        self.consumer.store = None
        self.response = Message.fromOpenIDArgs(
                                  {'response_nonce': mkNonce(),
                                   'ns': OPENID2_NS,
                                   })
        self.new_consumer._idResCheckNonce(self.response, self.endpoint)
        self.failUnlessLogEmpty()

    def test_tamperedNonce(self):
        """Malformed nonce"""
        self.response = Message.fromOpenIDArgs(
                                  {'ns': OPENID2_NS,
                                   'response_nonce': 'malformed'})
        self.assertRaises(VerificationError,
            self.new_consumer._idResCheckNonce, self.response, self.endpoint
        )

    def test_missingNonce(self):
        """no nonce parameter on the return_to"""
        self.response = Message.fromOpenIDArgs(
                                  {'return_to': self.return_to})
        self.assertRaises(VerificationError,
            self.new_consumer._idResCheckNonce, self.response, self.endpoint
        )


@mock.patch.object(Consumer, '_idResCheckNonce', mock.Mock(return_value=True))
@mock.patch.object(GenericConsumer, '_checkAuth', mock.Mock(side_effect=CheckAuthHappened))
class TestCheckAuthTriggered(TestIdRes, CatchLogs):

    def setUp(self):
        TestIdRes.setUp(self)
        CatchLogs.setUp(self)

    def test_checkAuthTriggered(self):
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to,
            'openid.identity': self.server_id,
            'openid.assoc_handle': 'not_found',
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
        }
        try:
            result = self.new_consumer.complete(query, self.return_to)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r %s' %
                      (result, self.messages))

    def test_checkAuthTriggeredWithAssoc(self):
        # Store an association for this server that does not match the
        # handle that is in the message
        issued = time.time()
        lifetime = 1000
        assoc = association.Association(
            'handle', 'secret', issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, assoc)
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to,
            'openid.identity': self.server_id,
            'openid.assoc_handle': 'not_found',
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
        }
        try:
            result = self.new_consumer.complete(query, self.return_to)
        except CheckAuthHappened:
            pass
        else:
            self.fail('_checkAuth did not happen. Result was: %r' % (result,))

    def test_expiredAssoc(self):
        # Store an expired association for the server with the handle
        # that is in the message
        issued = time.time() - 10
        lifetime = 0
        handle = 'handle'
        assoc = association.Association(
            handle, 'secret', issued, lifetime, 'HMAC-SHA1')
        self.assertTrue(assoc.expiresIn <= 0)
        self.store.storeAssociation(self.server_url, assoc)

        message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to,
            'openid.identity': self.server_id,
            'openid.assoc_handle': handle,
            'openid.sig': GOODSIG,
            'openid.signed': 'identity,return_to',
        })
        self.assertRaises(
            VerificationError,
            self.new_consumer._idResCheckSignature, message, self.endpoint.server_url,
        )

    def test_newerAssoc(self):
        lifetime = 1000

        good_issued = time.time() - 10
        good_handle = 'handle'
        good_assoc = association.Association(
            good_handle, 'secret', good_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, good_assoc)

        bad_issued = time.time() - 5
        bad_handle = 'handle2'
        bad_assoc = association.Association(
            bad_handle, 'secret', bad_issued, lifetime, 'HMAC-SHA1')
        self.store.storeAssociation(self.server_url, bad_assoc)

        message = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'return_to': self.return_to,
            'identity': self.server_id,
            'assoc_handle': good_handle,
        })
        message = good_assoc.signMessage(message)
        info = self.new_consumer.complete(message.toPostArgs(), self.return_to)
        self.assertEqual(info.status, 'success', info.message)
        self.assertEqual(self.consumer_id, info.identity())


class ReturnTo(unittest.TestCase):
    '''
    Verifying the Return URL paramaters.
    From the specification "Verifying the Return URL"::

        To verify that the "openid.return_to" URL matches the URL that is
        processing this_checkReturnTo assertion:

         - The URL scheme, authority, and path MUST be the same between the
           two URLs.

         - Any query parameters that are present in the "openid.return_to"
           URL MUST also be present with the same values in the
           accepting URL.
    '''
    def test_missing(self):
        message = Message.fromPostArgs({'openid.mode': 'id_res'})
        self.assertTrue(message.validate_return_to('http://example.com/'))

    def test_bad_url(self):
        message = Message.fromPostArgs({'openid.return_to': 'http://unittest/complete'})
        self.assertTrue(message.validate_return_to('http://fraud/complete'))
        self.assertTrue(message.validate_return_to('http://unittest/complete/'))
        self.assertTrue(message.validate_return_to('https://unittest/complete'))

    def test_good_args(self):
        message = Message.fromPostArgs({
            'openid.return_to': 'http://example.com/?foo=bar',
            'foo': 'bar',
            'stray': 'value', # unknown values are okay
        })
        self.assertFalse(message.validate_return_to('http://example.com/'))

    def test_bad_args(self):
        message = Message.fromPostArgs({
            'openid.mode': 'id_res',
            'openid.return_to': 'http://example.com/?foo=bar&xxx=yyy',
            'xxx': 'not yyy',
        })
        errors = message.validate_return_to('http://example.com/')
        self.assertTrue('foo, xxx' in errors[0])


class MockFetcher(object):
    def __init__(self, response=None):
        self.response = response
        self.fetches = []

    def fetch(self, url, body=None, headers=None):
        self.fetches.append((url, body, headers))
        return self.response


class ExceptionRaisingMockFetcher(object):
    class MyException(Exception):
        pass

    def fetch(self, url, body=None, headers=None):
        raise self.MyException('mock fetcher exception')


class BadArgCheckingConsumer(GenericConsumer):
    def _makeKVPost(self, args, _):
        assert args == {
            'openid.mode': 'check_authentication',
            'openid.signed': 'foo',
            'openid.ns': OPENID1_NS
            }, args
        return None


class TestCheckAuth(unittest.TestCase, CatchLogs):
    consumer_class = GenericConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = memstore.MemoryStore()

        self.consumer = self.consumer_class(self.store)

        self._original = fetchers.fetch
        self.fetcher = MockFetcher()
        fetchers.fetch = self.fetcher.fetch

    def tearDown(self):
        CatchLogs.tearDown(self)
        fetchers.fetch = self._original

    def test_error(self):
        self.fetcher.response = HTTPResponse(
            'http://some_url', 404, {'Hea': 'der'}, b'blah:blah\n')
        query = {'openid.signed': 'stuff',
                 'openid.stuff': 'a value'}
        r = self.consumer._checkAuth(Message.fromPostArgs(query),
                                     http_server_url)
        self.assertFalse(r)
        self.assertTrue(self.messages)

    def test_bad_args(self):
        query = {
            'openid.signed': 'foo',
            'closid.foo': 'something',
            }
        consumer = BadArgCheckingConsumer(self.store)
        consumer._checkAuth(Message.fromPostArgs(query), 'does://not.matter')

    def test_signedList(self):
        query = Message.fromOpenIDArgs({
            'mode': 'id_res',
            'sig': 'rabbits',
            'identity': '=example',
            'assoc_handle': 'munchkins',
            'ns.sreg': 'urn:sreg',
            'sreg.email': 'bogus@example.com',
            'signed': 'identity,mode,ns.sreg,sreg.email',
            'foo': 'bar',
            })
        args = self.consumer._createCheckAuthRequest(query)
        self.assertTrue(args.isOpenID1())
        for signed_arg in query.getArg(OPENID_NS, 'signed').split(','):
            self.assertTrue(args.getAliasedArg(signed_arg), signed_arg)

    def test_112(self):
        args = {
            'openid.assoc_handle': 'fa1f5ff0-cde4-11dc-a183-3714bfd55ca8',
            'openid.claimed_id': 'http://binkley.lan/user/test01',
            'openid.identity': 'http://test01.binkley.lan/',
            'openid.mode': 'id_res',
            'openid.ns': 'http://specs.openid.net/auth/2.0',
            'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0',
            'openid.op_endpoint': 'http://binkley.lan/server',
            'openid.pape.auth_policies': 'none',
            'openid.pape.auth_time': '2008-01-28T20:42:36Z',
            'openid.pape.nist_auth_level': '0',
            'openid.response_nonce': '2008-01-28T21:07:04Z99Q=',
            'openid.return_to': 'http://binkley.lan:8001/process?janrain_nonce=2008-01-28T21%3A07%3A02Z0tMIKx',
            'openid.sig': 'YJlWH4U6SroB1HoPkmEKx9AyGGg=',
            'openid.signed': 'assoc_handle,identity,response_nonce,return_to,claimed_id,op_endpoint,pape.auth_time,ns.pape,pape.nist_auth_level,pape.auth_policies'
        }
        self.assertEqual(OPENID2_NS, args['openid.ns'])
        incoming = Message.fromPostArgs(args)
        self.assertTrue(incoming.isOpenID2())
        car = self.consumer._createCheckAuthRequest(incoming)
        expected_args = args.copy()
        expected_args['openid.mode'] = 'check_authentication'
        expected = Message.fromPostArgs(expected_args)
        self.assertTrue(expected.isOpenID2())
        self.assertEqual(expected, car)
        car_args = car.toPostArgs()
        self.assertEqual(set(expected_args.keys()), set(car_args.keys()))
        self.assertEqual(set(expected_args.values()), set(car_args.values()))
        self.assertEqual(expected_args, car.toPostArgs())


class TestFetchAssoc(unittest.TestCase, CatchLogs):
    consumer_class = GenericConsumer

    def setUp(self):
        CatchLogs.setUp(self)
        self.store = memstore.MemoryStore()
        self._original = fetchers.fetch
        self.fetcher = MockFetcher()
        fetchers.fetch = self.fetcher.fetch
        self.consumer = self.consumer_class(self.store)

    def tearDown(self):
        fetchers.fetch = self._original

    def test_error_exception_unwrapped(self):
        """Ensure that exceptions are bubbled through from fetchers
        when making associations
        """
        self.fetcher = ExceptionRaisingMockFetcher()
        with mock.patch('openid.fetchers.fetch', self.fetcher.fetch):
            self.assertRaises(self.fetcher.MyException,
                                  makeKVPost,
                                  Message.fromPostArgs({'mode': 'associate'}),
                                  "http://server_url")

            # exception fetching returns no association
            e = Service()
            e.server_url = 'some://url'
            self.assertRaises(self.fetcher.MyException,
                                  self.consumer._getAssociation, e)

            self.assertRaises(self.fetcher.MyException,
                                  self.consumer._checkAuth,
                                  Message.fromPostArgs({'openid.signed': ''}),
                                  'some://url')


class TestSuccessResponse(unittest.TestCase):
    def setUp(self):
        self.endpoint = Service()
        self.endpoint.claimed_id = 'identity_url'

    def test_extensionResponse(self):
        resp = mkSuccess(self.endpoint, {
            'ns.sreg': 'urn:sreg',
            'ns.unittest': 'urn:unittest',
            'unittest.one': '1',
            'unittest.two': '2',
            'sreg.nickname': 'j3h',
            'return_to': 'return_to',
            })
        utargs = resp.extensionResponse('urn:unittest', False)
        self.assertEqual(utargs, {'one': '1', 'two': '2'})
        sregargs = resp.extensionResponse('urn:sreg', False)
        self.assertEqual(sregargs, {'nickname': 'j3h'})

    def test_extensionResponseSigned(self):
        args = {
            'ns.sreg': 'urn:sreg',
            'ns.unittest': 'urn:unittest',
            'unittest.one': '1',
            'unittest.two': '2',
            'sreg.nickname': 'j3h',
            'sreg.dob': 'yesterday',
            'return_to': 'return_to',
            'signed': 'sreg.nickname,unittest.one,sreg.dob',
            }

        signed_list = ['openid.sreg.nickname',
                       'openid.unittest.one',
                       'openid.sreg.dob']

        # Don't use mkSuccess because it creates an all-inclusive
        # signed list.
        msg = Message.fromOpenIDArgs(args)
        resp = SuccessResponse(self.endpoint, msg, signed_list)

        # All args in this NS are signed, so expect all.
        sregargs = resp.extensionResponse('urn:sreg', True)
        self.assertEqual(sregargs, {
                'nickname': 'j3h',
                'dob': 'yesterday'
                })

        # Not all args in this NS are signed, so expect None when
        # asking for them.
        utargs = resp.extensionResponse('urn:unittest', True)
        self.assertEqual(utargs, None)

    def test_noReturnTo(self):
        resp = mkSuccess(self.endpoint, {})
        self.assertTrue(resp.getReturnTo() is None)

    def test_returnTo(self):
        resp = mkSuccess(self.endpoint, {'return_to': 'return_to'})
        self.assertEqual(resp.getReturnTo(), 'return_to')


def _beginWithoutDiscovery(self, service, anonymous=False):
    request = AuthRequest(service, None)
    self.consumer.endpoint = service
    self.session[self._token_key] = request.endpoint
    try:
        request.setAnonymous(anonymous)
    except ValueError as why:
        raise ProtocolError(str(why))
    return request

@mock.patch.object(Consumer, 'beginWithoutDiscovery', _beginWithoutDiscovery)
class ConsumerTest(unittest.TestCase):
    """Tests for high-level consumer.Consumer functions.

    Its GenericConsumer component is stubbed out with StubConsumer.
    """
    def setUp(self):
        self.identity = 'http://identity.url/'
        self.endpoint = Service([], '', self.identity)
        self.store = None
        self.session = {}
        self.consumer = Consumer(self.session, self.store)

    def test_setAssociationPreference(self):
        self.consumer.setAssociationPreference([])
        self.assertTrue(isinstance(self.consumer.consumer.negotiator,
                                   association.SessionNegotiator))
        self.assertEqual([],
                             self.consumer.consumer.negotiator.allowed_types)
        self.consumer.setAssociationPreference([('HMAC-SHA1', 'DH-SHA1')])
        self.assertEqual([('HMAC-SHA1', 'DH-SHA1')],
                             self.consumer.consumer.negotiator.allowed_types)

    def test_beginWithoutDiscovery(self):
        # Does this really test anything non-trivial?
        result = self.consumer.beginWithoutDiscovery(self.endpoint)

        # The result is an auth request
        self.assertTrue(isinstance(result, AuthRequest))

        # Side-effect of calling beginWithoutDiscovery is setting the
        # session value to the endpoint attribute of the result
        self.assertTrue(
            self.session[self.consumer._token_key] is result.endpoint)

        # The endpoint that we passed in is the endpoint on the auth_request
        self.assertTrue(result.endpoint is self.endpoint)


@mock.patch('urllib.request.urlopen', support.urlopen)
class Cleanup(unittest.TestCase):
    def setUp(self):
        self.claimed_id = 'http://unittest/identity'
        self.session = {}
        self.consumer = Consumer(self.session, GoodAssocStore())
        self.consumer.session[self.consumer._token_key] = Service([OPENID_1_1_TYPE], '', self.claimed_id)
        self.return_to = 'http://unittest/complete'

    def test_success_session(self):
        nonce = mkNonce()
        query = {
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to + '?' + urllib.parse.urlencode({NONCE_ARG: nonce}),
            'openid.identity': self.claimed_id,
            NONCE_ARG: nonce,
            'openid.assoc_handle': 'z',
            'openid.signed': 'identity,return_to',
            'openid.sig': GOODSIG,
        }
        self.consumer.complete(query, self.return_to)
        self.assertFalse(self.consumer._token_key in self.session)

    def test_failure_session(self):
        self.assertRaises(VerificationError,
            self.consumer.complete, {}, self.return_to
        )
        self.assertFalse(self.consumer._token_key in self.session)


@mock.patch('urllib.request.urlopen', support.urlopen)
class IDPDrivenTest(unittest.TestCase):
    def setUp(self):
        self.store = GoodAssocStore()
        self.consumer = Consumer({}, self.store)
        self.endpoint = Service([OPENID_IDP_2_0_TYPE], 'http://unittest/')
        self.consumer.session[self.consumer._token_key] = self.endpoint
        self.return_to = 'http://unittest/complete'
        self.query = _nsdict({
            'openid.mode': 'id_res',
            'openid.return_to': self.return_to,
            'openid.op_endpoint': 'http://www.myopenid.com/server',
            'openid.claimed_id': 'http://unittest/openid2_xrds.xrds',
            'openid.identity': 'http://smoker.myopenid.com/',
            'openid.response_nonce': mkNonce(),
            'openid.assoc_handle': 'z',
            'openid.signed': 'return_to,identity,response_nonce,claimed_id,assoc_handle,op_endpoint',
            'openid.sig': GOODSIG,
        })

    def test_idpDrivenBegin(self):
        # Testing here that the token-handling doesn't explode...
        self.consumer.beginWithoutDiscovery(self.endpoint)

    def test_idpDrivenComplete(self):
        response = self.consumer.complete(self.query, self.return_to)
        self.assertEqual(response.status, 'success', str(response))

    def test_idpDrivenCompleteFraud(self):
        self.query['openid.claimed_id'] = 'http://unittest/openid2_xrds_no_local_id.xrds'
        self.assertRaises(VerificationError,
            self.consumer.complete, self.query, self.return_to
        )


@mock.patch('urllib.request.urlopen', support.urlopen)
class DiscoveryVerification(unittest.TestCase):
    def setUp(self):
        self.consumer = Consumer({}, None)
        self.identifier = 'http://unittest/openid2_xrds.xrds'
        self.local_id = 'http://smoker.myopenid.com/'
        self.server_url = 'http://www.myopenid.com/server'
        self.message1 = Message.fromPostArgs({
            'openid.ns': OPENID1_NS,
            'openid.identity': self.local_id,
        })
        self.message2 = Message.fromPostArgs({
            'openid.ns': OPENID2_NS,
            'openid.op_endpoint': self.server_url,
            'openid.claimed_id': self.identifier,
            'openid.identity': self.local_id,
        })
        self.endpoint = Service(
            [OPENID_2_0_TYPE],
            self.server_url,
            self.identifier,
            self.local_id,
        )

    def test_prediscovered_match(self):
        self.assertFalse(self.consumer._verify_openid2(self.message2, self.endpoint))

    def test_openid1_prediscovered_match(self):
        self.endpoint.types = [OPENID_1_1_TYPE]
        self.assertFalse(self.consumer._verify_openid1(self.message1, self.endpoint))

    def test_fragment(self):
        claimed_id = self.identifier + '#fragment'
        self.message2.setArg(OPENID2_NS, 'claimed_id', claimed_id)
        self.assertFalse(self.consumer._verify_openid2(self.message2, self.endpoint))

    def test_prediscovered_wrong_type(self):
        self.assertRaises(
            VerificationError,
            self.consumer._verify_openid1, self.message1, self.endpoint
        )

    def test_openid1_no_endpoint(self):
        self.assertRaises(
            VerificationError,
            self.consumer._verify_openid1, self.message1, None
        )

    def test_openid2_claimed_id_local_id(self):
        variants = [
            {
                'openid.op_endpoint': self.server_url,
                'openid.identity': self.identifier,
            },
            {
                'openid.op_endpoint': self.server_url,
                'openid.claimed_id': self.identifier,
            },
        ]
        for q in variants:
            self.assertTrue(self.consumer._verify_openid2(
                Message.fromPostArgs(_nsdict(q)),
                self.endpoint,
            ))

    def test_openid2_no_claimed_id(self):
        endpoint = Service([OPENID_IDP_2_0_TYPE], self.server_url)
        self.message2.delArg(OPENID2_NS, 'claimed_id')
        self.message2.delArg(OPENID2_NS, 'identity')
        self.assertFalse(self.consumer._verify_openid2(self.message2, endpoint))

    def test_wrong_info(self):
        endpoints = [
            Service([OPENID_2_0_TYPE], 'wrong', self.identifier, self.local_id),
            Service([OPENID_2_0_TYPE], self.server_url, self.identifier, 'wrong'),
        ]
        for endpoint in endpoints:
            self.assertTrue(self.consumer._verify_openid2(self.message2, endpoint))

    def test_rediscover(self):
        with mock.patch('openid.consumer.discover.discover') as discover:
            discover.return_value = self.endpoint
            self.consumer._verify_openid2(self.message2, None)
            discover.assert_called_once_with(self.identifier)

            discover.reset_mock()
            self.consumer._verify_openid2(self.message2, self.endpoint)
            self.assertFalse(discover.call_count)


class TestCreateAssociationRequest(unittest.TestCase):
    def setUp(self):
        class DummyEndpoint(object):
            use_compatibility = False

            def compat_mode(self):
                return self.use_compatibility

        self.endpoint = DummyEndpoint()
        self.consumer = GenericConsumer(store=None)
        self.assoc_type = 'HMAC-SHA1'

    def test_noEncryptionSendsType(self):
        session_type = 'no-encryption'
        session, args = self.consumer._createAssociateRequest(
            self.endpoint, self.assoc_type, session_type)

        self.assertTrue(isinstance(session, PlainTextConsumerSession))
        expected = Message.fromOpenIDArgs(
            {'ns': OPENID2_NS,
             'session_type': session_type,
             'mode': 'associate',
             'assoc_type': self.assoc_type,
             })

        self.assertEqual(expected, args)

    def test_noEncryptionCompatibility(self):
        self.endpoint.use_compatibility = True
        session_type = 'no-encryption'
        session, args = self.consumer._createAssociateRequest(
            self.endpoint, self.assoc_type, session_type)

        self.assertTrue(isinstance(session, PlainTextConsumerSession))
        self.assertEqual(Message.fromOpenIDArgs({
                    'mode': 'associate',
                    'assoc_type': self.assoc_type,
                    }), args)

    @mock.patch('openid.consumer.consumer.create_session', create_session)
    def test_dhSHA1Compatibility(self):
        self.endpoint.use_compatibility = True
        session_type = 'DH-SHA1'
        session, args = self.consumer._createAssociateRequest(
            self.endpoint, self.assoc_type, session_type)

        self.assertTrue(isinstance(session, DiffieHellmanSHA1ConsumerSession))

        # This is a random base-64 value, so just check that it's
        # present.
        self.assertTrue(args.getArg(OPENID1_NS, 'dh_consumer_public'))
        args.delArg(OPENID1_NS, 'dh_consumer_public')

        # OK, session_type is set here and not for no-encryption
        # compatibility
        expected = Message.fromOpenIDArgs({
            'mode': 'associate',
            'session_type': 'DH-SHA1',
            'assoc_type': self.assoc_type,
            # DH does byte-manipulation and returns bytes
            'dh_modulus': b'BfvStQ==',
            'dh_gen': b'Ag==',
        })

        self.assertEqual(expected, args)

    # XXX: test the other types


class _TestingDiffieHellmanResponseParameters(object):

    session_cls = None
    message_namespace = None

    def setUp(self):
        # Pre-compute DH with small prime so tests run quickly.
        self.server_dh = DiffieHellman(100389557, 2)
        self.consumer_dh = DiffieHellman(100389557, 2)

        # base64(btwoc(g ^ xb mod p))
        self.dh_server_public = cryptutil.longToBase64(self.server_dh.public)

        self.secret = cryptutil.randomString(self.session_cls.secret_size)

        self.enc_mac_key = oidutil.toBase64(
            self.server_dh.xorSecret(self.consumer_dh.public,
                                     self.secret,
                                     self.session_cls.hash_func))

        self.consumer_session = self.session_cls(self.consumer_dh)

        self.msg = Message(self.message_namespace)

    def testExtractSecret(self):
        self.msg.setArg(OPENID_NS, 'dh_server_public', self.dh_server_public)
        self.msg.setArg(OPENID_NS, 'enc_mac_key', self.enc_mac_key)

        extracted = self.consumer_session.extractSecret(self.msg)
        self.assertEqual(extracted, self.secret)

    def testAbsentServerPublic(self):
        self.msg.setArg(OPENID_NS, 'enc_mac_key', self.enc_mac_key)

        self.assertRaises(KeyError, self.consumer_session.extractSecret,
                              self.msg)

    def testAbsentMacKey(self):
        self.msg.setArg(OPENID_NS, 'dh_server_public', self.dh_server_public)

        self.assertRaises(KeyError, self.consumer_session.extractSecret,
                              self.msg)

    def testInvalidBase64Public(self):
        self.msg.setArg(OPENID_NS, 'dh_server_public', 'n o t b a s e 6 4.')
        self.msg.setArg(OPENID_NS, 'enc_mac_key', self.enc_mac_key)

        self.assertRaises(ValueError,
                              self.consumer_session.extractSecret,
                              self.msg)

    def testInvalidBase64MacKey(self):
        self.msg.setArg(OPENID_NS, 'dh_server_public', self.dh_server_public)
        self.msg.setArg(OPENID_NS, 'enc_mac_key', 'n o t base 64')

        self.assertRaises(ValueError,
                              self.consumer_session.extractSecret,
                              self.msg)


class TestOpenID1SHA1(_TestingDiffieHellmanResponseParameters,
                      unittest.TestCase):
    session_cls = DiffieHellmanSHA1ConsumerSession
    message_namespace = OPENID1_NS


class TestOpenID2SHA1(_TestingDiffieHellmanResponseParameters,
                      unittest.TestCase):
    session_cls = DiffieHellmanSHA1ConsumerSession
    message_namespace = OPENID2_NS

if cryptutil.SHA256_AVAILABLE:

    class TestOpenID2SHA256(_TestingDiffieHellmanResponseParameters,
                            unittest.TestCase):
        session_cls = DiffieHellmanSHA256ConsumerSession
        message_namespace = OPENID2_NS
else:
    warnings.warn("Not running SHA256 association session tests.")


class TestNoStore(unittest.TestCase):
    def setUp(self):
        self.consumer = Consumer({}, None)

    def test_completeNoGetAssoc(self):
        """_getAssociation is never called when the store is None"""
        def notCalled(unused):
            self.fail('This method was unexpectedly called')

        endpoint = Service([], '', 'identity_url')
        self.consumer.consumer._getAssociation = notCalled
        auth_request = self.consumer.beginWithoutDiscovery(endpoint)
        # _getAssociation was not called


class TestConsumerAnonymous(unittest.TestCase):
    def test_beginWithoutDiscoveryAnonymousFail(self):
        """Make sure that ValueError for setting an auth request
        anonymous gets converted to a ProtocolError
        """
        with mock.patch.object(AuthRequest,
                               'setAnonymous',
                               mock.Mock(side_effect=ValueError)):
            consumer = Consumer({}, None)
            self.assertRaises(
                ProtocolError,
                consumer.beginWithoutDiscovery, Service([], '')
            )


class SillyExtension(Extension):
    ns_uri = 'http://silly.example.com/'
    ns_alias = 'silly'

    def getExtensionArgs(self):
        return {'i_am': 'silly'}


class TestAddExtension(unittest.TestCase):
    def test_SillyExtension(self):
        ext = SillyExtension()
        ar = AuthRequest(Service(), None)
        ar.addExtension(ext)
        ext_args = ar.message.getArgs(ext.ns_uri)
        self.assertEqual(ext.getExtensionArgs(), ext_args)

def kvpost_fetch(url, body=None, headers=None):
    status = int(url.rsplit('/', 1)[1])
    if 200 <= status < 300:
        return HTTPResponse(url, status, body=b'foo:bar\nbaz:quux\n')
    if 400 <= status < 500:
        raise urllib.error.HTTPError(url, status, 'Test request failed', {}, io.BytesIO(b'error:bonk\nerror_code:7\n'))
    if 500 <= status:
        raise urllib.error.URLError('%s: 500' % url)

@mock.patch('openid.fetchers.fetch', kvpost_fetch)
class TestKVPost(unittest.TestCase):
    def test_200(self):
        r = makeKVPost(Message(), 'http://test-kv-post/200')
        expected_msg = Message.fromOpenIDArgs({'foo': 'bar', 'baz': 'quux'})
        self.assertEqual(expected_msg, r)

    def test_400(self):
        try:
            r = makeKVPost(Message(), 'http://test-kv-post/400')
        except ServerError as e:
            self.assertEqual(e.error_text, 'bonk')
            self.assertEqual(e.error_code, '7')
        else:
            self.fail("Expected ServerError, got return %r" % (r,))

    def test_500(self):
        with self.assertRaises(urllib.error.URLError):
            makeKVPost(Message(), 'http://test-kv-post/500')


if __name__ == '__main__':
    unittest.main()
