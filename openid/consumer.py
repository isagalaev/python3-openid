# -*- test-case-name: openid.test.test_consumer -*-
"""OpenID support for Relying Parties (aka Consumers).

This module documents the main interface with the OpenID consumer
library.  The only part of the library which has to be used and isn't
documented in full here is the store required to create an
C{L{Consumer}} instance.  More on the abstract store type and
concrete implementations of it that are provided in the documentation
for the C{L{__init__<Consumer.__init__>}} method of the
C{L{Consumer}} class.


OVERVIEW
========

    The OpenID identity verification process most commonly uses the
    following steps, as visible to the user of this library:

        1. The user enters their OpenID into a field on the consumer's
           site, and hits a login button.

        2. The consumer site discovers the user's OpenID provider using
           the Yadis protocol.

        3. The consumer site sends the browser a redirect to the
           OpenID provider.  This is the authentication request as
           described in the OpenID specification.

        4. The OpenID provider's site sends the browser a redirect
           back to the consumer site.  This redirect contains the
           provider's response to the authentication request.

    The most important part of the flow to note is the consumer's site
    must handle two separate HTTP requests in order to perform the
    full identity check.


LIBRARY DESIGN
==============

    This consumer library is designed with that flow in mind.  The
    goal is to make it as easy as possible to perform the above steps
    securely.

    At a high level, there are two important parts in the consumer
    library.  The first important part is this module, which contains
    the interface to actually use this library.  The second is the
    C{L{openid.store.interface}} module, which describes the
    interface to use if you need to create a custom method for storing
    the state this library needs to maintain between requests.

    In general, the second part is less important for users of the
    library to know about, as several implementations are provided
    which cover a wide variety of situations in which consumers may
    use the library.

    This module contains a class, C{L{Consumer}}, with methods
    corresponding to the actions necessary in each of steps 2, 3, and
    4 described in the overview.  Use of this library should be as easy
    as creating an C{L{Consumer}} instance and calling the methods
    appropriate for the action the site wants to take.


SESSIONS, STORES, AND STATELESS MODE
====================================

    The C{L{Consumer}} object keeps track of two types of state:

        1. State of the user's current authentication attempt.  Things like
           the identity URL, the list of endpoints discovered for that
           URL, and in case where some endpoints are unreachable, the list
           of endpoints already tried.  This state needs to be held from
           Consumer.begin() to Consumer.complete(), but it is only applicable
           to a single session with a single user agent, and at the end of
           the authentication process (i.e. when an OP replies with either
           C{id_res} or C{cancel}) it may be discarded.

        2. State of relationships with servers, i.e. shared secrets
           (associations) with servers and nonces seen on signed messages.
           This information should persist from one session to the next and
           should not be bound to a particular user-agent.


    These two types of storage are reflected in the first two arguments of
    Consumer's constructor, C{session} and C{store}.  C{session} is a
    dict-like object and we hope your web framework provides you with one
    of these bound to the user agent.  C{store} is an instance of
    L{openid.store.interface.OpenIDStore}.

    Since the store does hold secrets shared between your application and the
    OpenID provider, you should be careful about how you use it in a shared
    hosting environment.  If the filesystem or database permissions of your
    web host allow strangers to read from them, do not store your data there!
    If you have no safe place to store your data, construct your consumer
    with C{None} for the store, and it will operate only in stateless mode.
    Stateless mode may be slower, put more load on the OpenID provider, and
    trusts the provider to keep you safe from replay attacks.


    Several store implementation are provided, and the interface is
    fully documented so that custom stores can be used as well.  See
    the documentation for the C{L{Consumer}} class for more
    information on the interface for stores.  The implementations that
    are provided allow the consumer site to store the necessary data
    in several different ways, including several SQL databases and
    normal files on disk.


IMMEDIATE MODE
==============

    In the flow described above, the user may need to confirm to the
    OpenID provider that it's ok to disclose his or her identity.
    The provider may draw pages asking for information from the user
    before it redirects the browser back to the consumer's site.  This
    is generally transparent to the consumer site, so it is typically
    ignored as an implementation detail.

    There can be times, however, where the consumer site wants to get
    a response immediately.  When this is the case, the consumer can
    put the library in immediate mode.  In immediate mode, there is an
    extra response possible from the server, which is essentially the
    server reporting that it doesn't have enough information to answer
    the question yet.


USING THIS LIBRARY
==================

    Integrating this library into an application is usually a
    relatively straightforward process.  The process should basically
    follow this plan:

    Add an OpenID login field somewhere on your site.  When an OpenID
    is entered in that field and the form is submitted, it should make
    a request to your site which includes that OpenID URL.

    First, the application should L{instantiate a Consumer<Consumer.__init__>}
    with a session for per-user state and store for shared state.
    using the store of choice.

    Next, the application should call the 'C{L{begin<Consumer.begin>}}' method on the
    C{L{Consumer}} instance.  This method takes the OpenID URL.  The
    C{L{begin<Consumer.begin>}} method returns an C{L{AuthRequest}}
    object.

    Next, the application should call the
    C{L{redirectURL<AuthRequest.redirectURL>}} method on the
    C{L{AuthRequest}} object.  The parameter C{return_to} is the URL
    that the OpenID server will send the user back to after attempting
    to verify his or her identity.  The C{realm} parameter is the
    URL (or URL pattern) that identifies your web site to the user
    when he or she is authorizing it.  Send a redirect to the
    resulting URL to the user's browser.

    That's the first half of the authentication process.  The second
    half of the process is done after the user's OpenID Provider sends the
    user's browser a redirect back to your site to complete their
    login.

    When that happens, the user will contact your site at the URL
    given as the C{return_to} URL to the
    C{L{redirectURL<AuthRequest.redirectURL>}} call made
    above.  The request will have several query parameters added to
    the URL by the OpenID provider as the information necessary to
    finish the request.

    Get a C{L{Consumer}} instance with the same session and store as
    before and call its C{L{complete<Consumer.complete>}} method,
    passing in all the received query arguments.

    There are multiple possible return types possible from that
    method. These indicate whether or not the login was successful,
    and include any additional information appropriate for their type.
"""
import copy
import logging
import urllib.parse
import urllib.error

from openid import fetchers
from openid import discover
from openid.message import Message, OPENID_NS, OPENID2_NS, OPENID1_NS, \
     IDENTIFIER_SELECT, no_default, BARE_NS
from openid import cryptutil
from openid import oidutil
from openid import urinorm
from openid.association import Association, default_negotiator, \
     SessionNegotiator
from openid.dh import DiffieHellman
from openid.store.nonce import mkNonce, split as splitNonce


# The name of the query parameter that gets added to the return_to
# URL when using OpenID1. Don't make it start with 'openid',
# because it's not a standard protocol thing for OpenID1.
# OpenID2 has a standard parameter for it.
NONCE_ARG = 'janrain_nonce'


def makeKVPost(request_message, server_url):
    """Make a Direct Request to an OpenID Provider and return the
    result as a Message object.

    @raises urllib.error.URLError: if an error is
        encountered in making the HTTP post.

    @rtype: L{openid.message.Message}
    """
    try:
        response = fetchers.fetch(server_url, body=request_message.toURLEncoded())
        return Message.fromKVForm(response.read())
    except urllib.error.HTTPError as e:
        if e.code == 400:
            raise ServerError.fromMessage(Message.fromKVForm(e.read()))
        raise

def validate_fields(message):
    '''
    Checks for required fields and unsigned fields.
    Raises AuthenticationError if something's amiss.
    '''
    basic_fields = ['return_to', 'assoc_handle', 'sig', 'signed']
    basic_sig_fields = ['return_to', 'identity']

    require_fields = {
        OPENID2_NS: basic_fields + ['op_endpoint'],
        OPENID1_NS: basic_fields + ['identity'],
        }

    require_sigs = {
        OPENID2_NS: basic_sig_fields + ['response_nonce',
                                        'claimed_id',
                                        'assoc_handle',
                                        'op_endpoint'],
        OPENID1_NS: basic_sig_fields,
        }

    missing = [
        f for f in require_fields[message.getOpenIDNamespace()]
        if not message.hasKey(OPENID_NS, f)
    ]
    if missing:
        raise AuthenticationError('Missing fields: %s' % ', '.join(missing), message)

    signed_list = message.getArg(OPENID_NS, 'signed', '').split(',')
    unsigned = [
        f for f in require_sigs[message.getOpenIDNamespace()]
        if message.hasKey(OPENID_NS, f) and f not in signed_list
    ]
    if unsigned:
        raise AuthenticationError('Unsigned fields: %s' % ', '.join(unsigned), message)


def validate_return_to(message, return_to):
    '''
    Check an OpenID message and its openid.return_to value
    against a return_to URL from an application.
    Returns an error dict.
    '''
    msg_return_to = message.getArg(OPENID_NS, 'return_to')
    parsed_url = urllib.parse.urlparse(msg_return_to)
    rt_query = parsed_url[4]
    parsed_args = urllib.parse.parse_qsl(rt_query)

    args = [
        key for key, value in parsed_args
        if value != message.getArg(BARE_NS, key, None)
    ]
    if args:
        raise AuthenticationError('Mismatched return_to args: %s' % ', '.join(args), message)

    app_parts = urllib.parse.urlparse(urinorm.urinorm(return_to))
    msg_parts = urllib.parse.urlparse(urinorm.urinorm(msg_return_to) if msg_return_to else '')
    if app_parts[:3] != msg_parts[:3]:
        raise AuthenticationError('Wrong return_to: %s' % msg_return_to, message)


class Consumer(object):
    """An OpenID consumer implementation that performs discovery and
    does session management.

    @ivar consumer: an instance of an object implementing the OpenID
        protocol, but doing no discovery or session management.

    @type consumer: GenericConsumer

    @ivar session: A dictionary-like object representing the user's
        session data.  This is used for keeping state of the OpenID
        transaction when the user is redirected to the server.

    @cvar session_key_prefix: A string that is prepended to session
        keys to ensure that they are unique. This variable may be
        changed to suit your application.
    """
    session_key_prefix = "_openid_consumer_"

    _token = 'last_token'

    def __init__(self, session, store, consumer_class=None):
        """Initialize a Consumer instance.

        You should create a new instance of the Consumer object with
        every HTTP request that handles OpenID transactions.

        @param session: See L{the session instance variable<openid.consumer.Consumer.session>}

        @param store: an object that implements the interface in
            C{L{openid.store.interface.OpenIDStore}}.  Several
            implementations are provided, to cover common database
            environments.

        @type store: C{L{openid.store.interface.OpenIDStore}}

        @see: L{openid.store.interface}
        @see: L{openid.store}
        """
        self.session = session
        if consumer_class is None:
            consumer_class = GenericConsumer
        self.consumer = consumer_class(store)
        self._token_key = self.session_key_prefix + self._token

    def begin(self, user_url, anonymous=False):
        """Start the OpenID authentication process. See steps 1-2 in
        the overview at the top of this file.

        @param user_url: Identity URL given by the user. This method
            performs a textual transformation of the URL to try and
            make sure it is normalized. For example, a user_url of
            example.com will be normalized to http://example.com/
            normalizing and resolving any redirects the server might
            issue.

        @type user_url: unicode

        @param anonymous: Whether to make an anonymous request of the OpenID
            provider.  Such a request does not ask for an authorization
            assertion for an OpenID identifier, but may be used with
            extensions to pass other data.  e.g. "I don't care who you are,
            but I'd like to know your time zone."

        @type anonymous: bool

        @returns: An object containing the discovered information will
            be returned, with a method for building a redirect URL to
            the server, as described in step 3 of the overview. This
            object may also be used to add extension arguments to the
            request, using its
            L{addExtensionArg<openid.consumer.AuthRequest.addExtensionArg>}
            method.

        @returntype: L{AuthRequest<openid.consumer.AuthRequest>}
        """
        service = discover.discover(user_url)
        return self.beginWithoutDiscovery(service, anonymous)

    def beginWithoutDiscovery(self, service, anonymous=False):
        """Start OpenID verification without doing OpenID server
        discovery. This method is used internally by Consumer.begin
        after discovery is performed, and exists to provide an
        interface for library users needing to perform their own
        discovery.

        @param service: an OpenID service endpoint descriptor.  This
            object and factories for it are found in the
            L{openid.discover} module.

        @type service:
            L{Service<openid.discover.Service>}

        @returns: an OpenID authentication request object.

        @rtype: L{AuthRequest<openid.consumer.AuthRequest>}

        @See: Openid.consumer.Consumer.begin
        @see: openid.discover
        """
        if self.consumer.store is None:
            assoc = None
        else:
            assoc = self.consumer._getAssociation(service)

        request = AuthRequest(service, assoc)
        request.return_to_args[NONCE_ARG] = mkNonce()

        self.session[self._token_key] = request.endpoint.__dict__

        try:
            request.setAnonymous(anonymous)
        except ValueError as why:
            raise ProtocolError(str(why))

        return request

    def complete(self, query, current_url):
        """Called to interpret the server's response to an OpenID
        request. It is called in step 4 of the flow described in the
        consumer overview.

        @param query: A dictionary of the query parameters for this
            HTTP request.

        @param current_url: The URL used to invoke the application.
            Extract the URL from your application's web
            request framework and specify it here to have it checked
            against the openid.return_to value in the response.  If
            the return_to URL check fails, the status of the
            completion will be 'failure'.

        @returns: a subclass of Response. The type of response is
            indicated by the status attribute, which will be one of
            'success', 'cancel', or 'setup_needed'.
        """
        message = Message.fromPostArgs(query)
        data = self.session.pop(self._token_key, None)
        endpoint = discover.Service(**data) if data else None

        mode = message.getArg(OPENID_NS, 'mode')
        if mode in ['cancel', 'error']:
            if mode == 'cancel':
                error = 'Authentication cancelled by OpenID provider'
            raise AuthenticationError(message.getArg(OPENID_NS, 'error'), message)
        if (mode == 'setup_needed' and message.isOpenID2() or
            mode == 'id_res' and message.setup_url()):
            raise SetupNeeded(message)
        if mode != 'id_res':
            raise AuthenticationError('Mode missing or invalid: %s' % mode, message)

        self.verify_response(message, endpoint, current_url)

        signed_list = message.getArg(OPENID_NS, 'signed').split(',')
        signed_fields = ['openid.' + s for s in signed_list]
        claimed_id = endpoint.claimed_id if message.isOpenID1() else None
        return Response(message, signed_fields, claimed_id)

    def verify_response(self, message, endpoint, return_to):
        '''
        Verifies authentication response against the discovered information
        '''
        validate_fields(message)
        validate_return_to(message, return_to)
        func = '_verify_openid2' if message.getOpenIDNamespace() == OPENID2_NS else '_verify_openid1'
        getattr(self, func)(message, endpoint)
        self._idResCheckSignature(message, endpoint.server_url)
        self._idResCheckNonce(message, endpoint)

    def _idResCheckNonce(self, message, endpoint):
        if message.isOpenID1():
            nonce = message.getArg(BARE_NS, NONCE_ARG)
            server_url = ''
        else:
            nonce = message.getArg(OPENID2_NS, 'response_nonce')
            server_url = endpoint.server_url

        if nonce is None:
            raise AuthenticationError('Nonce missing from response', message)

        try:
            timestamp, salt = splitNonce(nonce)
        except ValueError as why:
            raise AuthenticationError('Malformed nonce: %s' % why, message)

        if (self.consumer.store is not None and
            not self.consumer.store.useNonce(server_url, timestamp, salt)):
            raise AuthenticationError('Nonce already used or out of range', message)

    def _idResCheckSignature(self, message, server_url):
        assoc_handle = message.getArg(OPENID_NS, 'assoc_handle')
        if self.consumer.store is None:
            assoc = None
        else:
            assoc = self.consumer.store.getAssociation(server_url, assoc_handle)

        if assoc:
            if assoc.expiresIn <= 0:
                # XXX: It might be a good idea sometimes to re-start the
                # authentication with a new association. Doing it
                # automatically opens the possibility for
                # denial-of-service by a server that just returns expired
                # associations (or really short-lived associations)
                raise AuthenticationError(
                    'Association with %s expired' % server_url, message)

            if not assoc.checkMessageSignature(message):
                raise AuthenticationError('Bad signature', message)

        else:
            # It's not an association we know about.  Stateless mode is our
            # only possible path for recovery.
            # XXX - async framework will not want to block on this call to
            # _checkAuth.
            if not self.consumer._checkAuth(message, server_url):
                raise AuthenticationError('Server denied check_authentication', message)

    def _verify_openid1(self, message, endpoint):
        if endpoint is None:
            raise AuthenticationError('Can\'t verify discovered info without a stored endpoint under OpenID 1', message)
        if not endpoint.compat_mode():
            raise AuthenticationError('Expected an OpenID 2 response', message)
        if message.getArg(OPENID1_NS, 'identity') != endpoint.identity():
            raise AuthenticationError('Bad identity: %s' % message.getArg(OPENID1_NS, 'identity'), message)

    def _verify_openid2(self, message, endpoint):
        claimed_id = message.getArg(OPENID2_NS, 'claimed_id')
        if claimed_id:
            claimed_id = urllib.parse.urldefrag(claimed_id)[0]
        identity = message.getArg(OPENID2_NS, 'identity')
        if (claimed_id is None) != (identity is None):
            raise AuthenticationError(
                'openid.identity and openid.claimed_id should be either both '
                'present or both absent',
                message
            )

        if endpoint is None or claimed_id != endpoint.claimed_id:
            if claimed_id is None:
                raise AuthenticationError(
                    'Can\'t verify discovered info without a stored endpoint or '
                    'claimed_id', message
                )
            endpoint = discover.discover(claimed_id)

        if endpoint.compat_mode():
            raise AuthenticationError('Expected an OpenID 1 response', message)
        if message.getArg(OPENID2_NS, 'op_endpoint') != endpoint.server_url:
            raise AuthenticationError('Bad OP Endpoint: %s' % message.getArg(OPENID2_NS, 'op_endpoint'), message)
        if claimed_id != endpoint.claimed_id:
            raise AuthenticationError('Bas Claimed ID: %s' % claimed_id, message)
        if identity != endpoint.local_id:
            raise AuthenticationError('Bad Identity: %s' % identity, message)

    def setAssociationPreference(self, association_preferences):
        """Set the order in which association types/sessions should be
        attempted. For instance, to only allow HMAC-SHA256
        associations created with a DH-SHA256 association session:

        >>> consumer.setAssociationPreference([('HMAC-SHA256', 'DH-SHA256')])

        Any association type/association type pair that is not in this
        list will not be attempted at all.

        @param association_preferences: The list of allowed
            (association type, association session type) pairs that
            should be allowed for this consumer to use, in order from
            most preferred to least preferred.
        @type association_preferences: [(str, str)]

        @returns: None

        @see: C{L{openid.association.SessionNegotiator}}
        """
        self.consumer.negotiator = SessionNegotiator(association_preferences)


class DiffieHellmanSHA1ConsumerSession(object):
    session_type = 'DH-SHA1'
    hash_func = staticmethod(cryptutil.sha1)
    secret_size = 20
    allowed_assoc_types = ['HMAC-SHA1']

    def __init__(self, dh=None):
        if dh is None:
            dh = DiffieHellman.fromDefaults()

        self.dh = dh

    def getRequest(self):
        cpub = cryptutil.longToBase64(self.dh.public)

        args = {'dh_consumer_public': cpub}

        if not self.dh.usingDefaultValues():
            args.update({
                'dh_modulus': cryptutil.longToBase64(self.dh.modulus),
                'dh_gen': cryptutil.longToBase64(self.dh.generator),
                })

        return args

    def extractSecret(self, response):
        dh_server_public64 = response.getArg(
            OPENID_NS, 'dh_server_public', no_default)
        enc_mac_key64 = response.getArg(OPENID_NS, 'enc_mac_key', no_default)
        dh_server_public = cryptutil.base64ToLong(dh_server_public64)
        enc_mac_key = oidutil.fromBase64(enc_mac_key64)
        return self.dh.xorSecret(dh_server_public, enc_mac_key, self.hash_func)


class DiffieHellmanSHA256ConsumerSession(DiffieHellmanSHA1ConsumerSession):
    session_type = 'DH-SHA256'
    hash_func = staticmethod(cryptutil.sha256)
    secret_size = 32
    allowed_assoc_types = ['HMAC-SHA256']


class PlainTextConsumerSession(object):
    session_type = 'no-encryption'
    allowed_assoc_types = ['HMAC-SHA1', 'HMAC-SHA256']

    def getRequest(self):
        return {}

    def extractSecret(self, response):
        mac_key64 = response.getArg(OPENID_NS, 'mac_key', no_default)
        return oidutil.fromBase64(mac_key64)

def create_session(type):
    return {
        'DH-SHA1': DiffieHellmanSHA1ConsumerSession,
        'DH-SHA256': DiffieHellmanSHA256ConsumerSession,
        'no-encryption': PlainTextConsumerSession,
    }[type]()


class ProtocolError(ValueError):
    """Exception that indicates that a message violated the
    protocol. It is raised and caught internally to this file."""


class AuthenticationError(ValueError):
    '''
    Base class for all non-normal conditions during handling authintication
    requests from a provider.
    '''
    def __init__(self, message, response):
        super().__init__(message)
        self.response = response

class SetupNeeded(AuthenticationError):
    '''
    Provider requires additional setup in response to an immediate request.
    '''
    def __init__(self, response):
        super().__init__('Setup needed', response)


class ServerError(Exception):
    """Exception that is raised when the server returns a 400 response
    code to a direct request."""

    def __init__(self, error_text, error_code, message):
        Exception.__init__(self, error_text)
        self.error_text = error_text
        self.error_code = error_code
        self.message = message

    def fromMessage(cls, message):
        """Generate a ServerError instance, extracting the error text
        and the error code from the message."""
        error_text = message.getArg(
            OPENID_NS, 'error', '<no error message supplied>')
        error_code = message.getArg(OPENID_NS, 'error_code')
        return cls(error_text, error_code, message)

    fromMessage = classmethod(fromMessage)


class GenericConsumer(object):
    """This is the implementation of the common logic for OpenID
    consumers. It is unaware of the application in which it is
    running.

    @ivar negotiator: An object that controls the kind of associations
        that the consumer makes. It defaults to
        C{L{openid.association.default_negotiator}}. Assign a
        different negotiator to it if you have specific requirements
        for how associations are made.
    @type negotiator: C{L{openid.association.SessionNegotiator}}
    """

    def __init__(self, store):
        self.store = store
        self.negotiator = default_negotiator.copy()

    def _checkAuth(self, message, server_url):
        """Make a check_authentication request to verify this message.

        @returns: True if the request is valid.
        @rtype: bool
        """
        logging.info('Using OpenID check_authentication')
        request = self._createCheckAuthRequest(message)
        if request is None:
            return False
        try:
            response = makeKVPost(request, server_url)
        except (urllib.error.URLError, ServerError) as e:
            e0 = e.args[0]
            logging.exception('check_authentication failed: %s' % e0)
            return False
        else:
            return self._processCheckAuthResponse(response, server_url)

    def _createCheckAuthRequest(self, message):
        """Generate a check_authentication request message given an
        id_res message.
        """
        signed = message.getArg(OPENID_NS, 'signed')
        if signed:
            if isinstance(signed, bytes):
                signed = str(signed, encoding="utf-8")
            for k in signed.split(','):
                logging.info(k)
                val = message.getAliasedArg(k)

                # Signed value is missing
                if val is None:
                    logging.info('Missing signed field %r' % (k,))
                    return None

        check_auth_message = message.copy()
        check_auth_message.setArg(OPENID_NS, 'mode', 'check_authentication')
        return check_auth_message

    def _processCheckAuthResponse(self, response, server_url):
        """Process the response message from a check_authentication
        request, invalidating associations if requested.
        """
        is_valid = response.getArg(OPENID_NS, 'is_valid', 'false')

        invalidate_handle = response.getArg(OPENID_NS, 'invalidate_handle')
        if invalidate_handle is not None:
            logging.info(
                'Received "invalidate_handle" from server %s' % (server_url,))
            if self.store is None:
                logging.error('Unexpectedly got invalidate_handle without '
                            'a store!')
            else:
                self.store.removeAssociation(server_url, invalidate_handle)

        if is_valid == 'true':
            return True
        else:
            logging.error('Server responds that checkAuth call is not valid')
            return False

    def _getAssociation(self, endpoint):
        """Get an association for the endpoint's server_url.

        First try seeing if we have a good association in the
        store. If we do not, then attempt to negotiate an association
        with the server.

        If we negotiate a good association, it will get stored.

        @returns: A valid association for the endpoint's server_url or None
        @rtype: openid.association.Association or NoneType
        """
        assoc = self.store.getAssociation(endpoint.server_url)

        if assoc is None or assoc.expiresIn <= 0:
            assoc = self._negotiateAssociation(endpoint)
            if assoc is not None:
                self.store.storeAssociation(endpoint.server_url, assoc)

        return assoc

    def _negotiateAssociation(self, endpoint):
        """Make association requests to the server, attempting to
        create a new association.

        @returns: a new association object

        @rtype: L{openid.association.Association}
        """
        # Get our preferred session/association type from the negotiatior.
        assoc_type, session_type = self.negotiator.getAllowedType()

        try:
            assoc = self._requestAssociation(
                endpoint, assoc_type, session_type)
        except ServerError as why:
            supportedTypes = self._extractSupportedAssociationType(why,
                                                                   endpoint,
                                                                   assoc_type)
            if supportedTypes is not None:
                assoc_type, session_type = supportedTypes
                # Attempt to create an association from the assoc_type
                # and session_type that the server told us it
                # supported.
                try:
                    assoc = self._requestAssociation(
                        endpoint, assoc_type, session_type)
                except ServerError as why:
                    # Do not keep trying, since it rejected the
                    # association type that it told us to use.
                    logging.error(
                        'Server %s refused its suggested association '
                        'type: session_type=%s, assoc_type=%s'
                        % (endpoint.server_url, session_type,
                           assoc_type))
                    return None
                else:
                    return assoc
        else:
            return assoc

    def _extractSupportedAssociationType(self, server_error, endpoint,
                                         assoc_type):
        """Handle ServerErrors resulting from association requests.

        @returns: If server replied with an C{unsupported-type} error,
            return a tuple of supported C{association_type}, C{session_type}.
            Otherwise logs the error and returns None.
        @rtype: tuple or None
        """
        # Any error message whose code is not 'unsupported-type'
        # should be considered a total failure.
        if server_error.error_code != 'unsupported-type' or \
               server_error.message.isOpenID1():
            logging.error(
                'Server error when requesting an association from %r: %s'
                % (endpoint.server_url, server_error.error_text))
            return None

        # The server didn't like the association/session type
        # that we sent, and it sent us back a message that
        # might tell us how to handle it.
        logging.error(
            'Unsupported association type %s: %s' % (assoc_type,
                                                     server_error.error_text,))

        # Extract the session_type and assoc_type from the
        # error message
        assoc_type = server_error.message.getArg(OPENID_NS, 'assoc_type')
        session_type = server_error.message.getArg(OPENID_NS, 'session_type')

        if assoc_type is None or session_type is None:
            logging.error('Server responded with unsupported association '
                        'session but did not supply a fallback.')
            return None
        elif not self.negotiator.isAllowed(assoc_type, session_type):
            fmt = ('Server sent unsupported session/association type: '
                   'session_type=%s, assoc_type=%s')
            logging.error(fmt % (session_type, assoc_type))
            return None
        else:
            return assoc_type, session_type

    def _requestAssociation(self, endpoint, assoc_type, session_type):
        """Make and process one association request to this endpoint's
        OP endpoint URL.

        @returns: An association object or None if the association
            processing failed.

        @raises ServerError: when the remote OpenID server returns an error.
        """
        assoc_session, args = self._createAssociateRequest(
            endpoint, assoc_type, session_type)

        try:
            response = makeKVPost(args, endpoint.server_url)
        except urllib.error.URLError as why:
            logging.exception('openid.associate request failed: %s' % why)
            return None

        try:
            assoc = self._extractAssociation(response, assoc_session)
        except KeyError as why:
            logging.exception(
                'Missing required parameter in response from %s: %s'
                % (endpoint.server_url, why))
            return None
        except ProtocolError as why:
            logging.exception('Protocol error parsing response from %s: %s' % (
                endpoint.server_url, why))
            return None
        else:
            return assoc

    def _createAssociateRequest(self, endpoint, assoc_type, session_type):
        """Create an association request for the given assoc_type and
        session_type.

        @param endpoint: The endpoint whose server_url will be
            queried. The important bit about the endpoint is whether
            it's in compatiblity mode (OpenID 1.1)

        @param assoc_type: The association type that the request
            should ask for.
        @type assoc_type: str

        @param session_type: The session type that should be used in
            the association request. The session_type is used to
            create an association session object, and that session
            object is asked for any additional fields that it needs to
            add to the request.
        @type session_type: str

        @returns: a pair of the association session object and the
            request message that will be sent to the server.
        @rtype: (association session type (depends on session_type),
                 openid.message.Message)
        """
        assoc_session = create_session(session_type)

        args = {
            'mode': 'associate',
            'assoc_type': assoc_type,
            }

        if not endpoint.compat_mode():
            args['ns'] = OPENID2_NS

        # Leave out the session type if we're in compatibility mode
        # *and* it's no-encryption.
        if (not endpoint.compat_mode() or
            assoc_session.session_type != 'no-encryption'):
            args['session_type'] = assoc_session.session_type

        args.update(assoc_session.getRequest())
        message = Message.fromOpenIDArgs(args)
        return assoc_session, message

    def _getOpenID1SessionType(self, assoc_response):
        """Given an association response message, extract the OpenID
        1.X session type.

        This function mostly takes care of the 'no-encryption' default
        behavior in OpenID 1.

        If the association type is plain-text, this function will
        return 'no-encryption'

        @returns: The association type for this message
        @rtype: str

        @raises KeyError: when the session_type field is absent.
        """
        # If it's an OpenID 1 message, allow session_type to default
        # to None (which signifies "no-encryption")
        session_type = assoc_response.getArg(OPENID1_NS, 'session_type')

        # Handle the differences between no-encryption association
        # respones in OpenID 1 and 2:

        # no-encryption is not really a valid session type for
        # OpenID 1, but we'll accept it anyway, while issuing a
        # warning.
        if session_type == 'no-encryption':
            logging.warning('OpenID server sent "no-encryption"'
                        'for OpenID 1.X')

        # Missing or empty session type is the way to flag a
        # 'no-encryption' response. Change the session type to
        # 'no-encryption' so that it can be handled in the same
        # way as OpenID 2 'no-encryption' respones.
        elif session_type == '' or session_type is None:
            session_type = 'no-encryption'

        return session_type

    def _extractAssociation(self, assoc_response, assoc_session):
        """Attempt to extract an association from the response, given
        the association response message and the established
        association session.

        @param assoc_response: The association response message from
            the server
        @type assoc_response: openid.message.Message

        @param assoc_session: The association session object that was
            used when making the request
        @type assoc_session: depends on the session type of the request

        @raises ProtocolError: when data is malformed
        @raises KeyError: when a field is missing

        @rtype: openid.association.Association
        """
        # Extract the common fields from the response, raising an
        # exception if they are not found
        assoc_type = assoc_response.getArg(
            OPENID_NS, 'assoc_type', no_default)
        assoc_handle = assoc_response.getArg(
            OPENID_NS, 'assoc_handle', no_default)

        # expires_in is a base-10 string. The Python parsing will
        # accept literals that have whitespace around them and will
        # accept negative values. Neither of these are really in-spec,
        # but we think it's OK to accept them.
        expires_in_str = assoc_response.getArg(
            OPENID_NS, 'expires_in', no_default)
        try:
            expires_in = int(expires_in_str)
        except ValueError as why:
            raise ProtocolError('Invalid expires_in field: %s' % (why,))

        # OpenID 1 has funny association session behaviour.
        if assoc_response.isOpenID1():
            session_type = self._getOpenID1SessionType(assoc_response)
        else:
            session_type = assoc_response.getArg(
                OPENID2_NS, 'session_type', no_default)

        # Session type mismatch
        if assoc_session.session_type != session_type:
            if (assoc_response.isOpenID1() and
                session_type == 'no-encryption'):
                # In OpenID 1, any association request can result in a
                # 'no-encryption' association response. Setting
                # assoc_session to a new no-encryption session should
                # make the rest of this function work properly for
                # that case.
                assoc_session = PlainTextConsumerSession()
            else:
                # Any other mismatch, regardless of protocol version
                # results in the failure of the association session
                # altogether.
                fmt = 'Session type mismatch. Expected %r, got %r'
                message = fmt % (assoc_session.session_type, session_type)
                raise ProtocolError(message)

        # Make sure assoc_type is valid for session_type
        if assoc_type not in assoc_session.allowed_assoc_types:
            fmt = 'Unsupported assoc_type for session %s returned: %s'
            raise ProtocolError(fmt % (assoc_session.session_type, assoc_type))

        # Delegate to the association session to extract the secret
        # from the response, however is appropriate for that session
        # type.
        try:
            secret = assoc_session.extractSecret(assoc_response)
        except ValueError as why:
            fmt = 'Malformed response for %s session: %s'
            raise ProtocolError(fmt % (assoc_session.session_type, why))

        return Association.fromExpiresIn(
            expires_in, assoc_handle, secret, assoc_type)


class AuthRequest(object):
    """An object that holds the state necessary for generating an
    OpenID authentication request. This object holds the association
    with the server and the discovered information with which the
    request will be made.

    It is separate from the consumer because you may wish to add
    things to the request before sending it on its way to the
    server. It also has serialization options that let you encode the
    authentication request as a URL or as a form POST.
    """

    def __init__(self, endpoint, assoc):
        """
        Creates a new AuthRequest object.  This just stores each
        argument in an appropriately named field.

        Users of this library should not create instances of this
        class.  Instances of this class are created by the library
        when needed.
        """
        self.assoc = assoc
        self.endpoint = endpoint
        self.return_to_args = {}
        self.message = Message(endpoint.ns())
        self._anonymous = False

    def setAnonymous(self, is_anonymous):
        """Set whether this request should be made anonymously. If a
        request is anonymous, the identifier will not be sent in the
        request. This is only useful if you are making another kind of
        request with an extension in this request.

        Anonymous requests are not allowed when the request is made
        with OpenID 1.

        @raises ValueError: when attempting to set an OpenID1 request
            as anonymous
        """
        if is_anonymous and self.message.isOpenID1():
            raise ValueError('OpenID 1 requests MUST include the '
                             'identifier in the request')
        else:
            self._anonymous = is_anonymous

    def addExtension(self, extension_request):
        """Add an extension to this checkid request.

        @param extension_request: An object that implements the
            extension interface for adding arguments to an OpenID
            message.
        """
        extension_request.toMessage(self.message)

    def addExtensionArg(self, namespace, key, value):
        """Add an extension argument to this OpenID authentication
        request.

        Use caution when adding arguments, because they will be
        URL-escaped and appended to the redirect URL, which can easily
        get quite long.

        @param namespace: The namespace for the extension. For
            example, the simple registration extension uses the
            namespace C{sreg}.

        @type namespace: str

        @param key: The key within the extension namespace. For
            example, the nickname field in the simple registration
            extension's key is C{nickname}.

        @type key: str

        @param value: The value to provide to the server for this
            argument.

        @type value: str
        """
        self.message.setArg(namespace, key, value)

    def getMessage(self, realm, return_to=None, immediate=False):
        """Produce a L{openid.message.Message} representing this request.

        @param realm: The URL (or URL pattern) that identifies your
            web site to the user when she is authorizing it.

        @type realm: str

        @param return_to: The URL that the OpenID provider will send the
            user back to after attempting to verify her identity.

            Not specifying a return_to URL means that the user will not
            be returned to the site issuing the request upon its
            completion.

        @type return_to: str

        @param immediate: If True, the OpenID provider is to send back
            a response immediately, useful for behind-the-scenes
            authentication attempts.  Otherwise the OpenID provider
            may engage the user before providing a response.  This is
            the default case, as the user may need to provide
            credentials or approve the request before a positive
            response can be sent.

        @type immediate: bool

        @returntype: L{openid.message.Message}
        """
        if return_to:
            return_to = oidutil.appendArgs(return_to, self.return_to_args)
        elif immediate:
            raise ValueError(
                '"return_to" is mandatory when using "checkid_immediate"')
        elif self.message.isOpenID1():
            raise ValueError('"return_to" is mandatory for OpenID 1 requests')
        elif self.return_to_args:
            raise ValueError('extra "return_to" arguments were specified, '
                             'but no return_to was specified')

        if immediate:
            mode = 'checkid_immediate'
        else:
            mode = 'checkid_setup'

        message = self.message.copy()
        if message.isOpenID1():
            realm_key = 'trust_root'
        else:
            realm_key = 'realm'

        message.updateArgs(OPENID_NS, {
                realm_key: realm,
                'mode': mode,
                'return_to': return_to,
                })

        if not self._anonymous:
            if self.endpoint.is_op_identifier():
                # This will never happen when we're in compatibility
                # mode, as long as is_op_identifier() returns False
                # whenever ns() returns OPENID1_NS.
                claimed_id = request_identity = IDENTIFIER_SELECT
            else:
                request_identity = self.endpoint.identity()
                claimed_id = self.endpoint.claimed_id

            # This is true for both OpenID 1 and 2
            message.setArg(OPENID_NS, 'identity', request_identity)

            if message.isOpenID2():
                message.setArg(OPENID2_NS, 'claimed_id', claimed_id)

        if self.assoc:
            message.setArg(OPENID_NS, 'assoc_handle', self.assoc.handle)
            assoc_log_msg = 'with association %s' % (self.assoc.handle,)
        else:
            assoc_log_msg = 'using stateless mode.'

        logging.info("Generated %s request to %s %s" %
                    (mode, self.endpoint.server_url, assoc_log_msg))

        return message

    def redirectURL(self, realm, return_to=None, immediate=False):
        """Returns a URL with an encoded OpenID request.

        The resulting URL is the OpenID provider's endpoint URL with
        parameters appended as query arguments.  You should redirect
        the user agent to this URL.

        OpenID 2.0 endpoints also accept POST requests, see
        C{L{shouldSendRedirect}} and C{L{formMarkup}}.

        @param realm: The URL (or URL pattern) that identifies your
            web site to the user when she is authorizing it.

        @type realm: str

        @param return_to: The URL that the OpenID provider will send the
            user back to after attempting to verify her identity.

            Not specifying a return_to URL means that the user will not
            be returned to the site issuing the request upon its
            completion.

        @type return_to: str

        @param immediate: If True, the OpenID provider is to send back
            a response immediately, useful for behind-the-scenes
            authentication attempts.  Otherwise the OpenID provider
            may engage the user before providing a response.  This is
            the default case, as the user may need to provide
            credentials or approve the request before a positive
            response can be sent.

        @type immediate: bool

        @returns: The URL to redirect the user agent to.

        @returntype: str
        """
        message = self.getMessage(realm, return_to, immediate)
        return message.toURL(self.endpoint.server_url)

    def formMarkup(self, realm, return_to=None, immediate=False,
            form_tag_attrs=None):
        """Get html for a form to submit this request to the IDP.

        @param form_tag_attrs: Dictionary of attributes to be added to
            the form tag. 'accept-charset' and 'enctype' have defaults
            that can be overridden. If a value is supplied for
            'action' or 'method', it will be replaced.
        @type form_tag_attrs: {unicode: unicode}
        """
        message = self.getMessage(realm, return_to, immediate)
        return message.toFormMarkup(self.endpoint.server_url,
                    form_tag_attrs)

    def htmlMarkup(self, realm, return_to=None, immediate=False,
            form_tag_attrs=None):
        """Get an autosubmitting HTML page that submits this request to the
        IDP.  This is just a wrapper for formMarkup.

        @see: formMarkup

        @returns: str
        """
        return oidutil.autoSubmitHTML(self.formMarkup(realm,
                                                      return_to,
                                                      immediate,
                                                      form_tag_attrs))

    def shouldSendRedirect(self):
        """Should this OpenID authentication request be sent as a HTTP
        redirect or as a POST (form submission)?

        @rtype: bool
        """
        return self.endpoint.compat_mode()


class Response:
    '''
    Indicates that this request is a
    successful acknowledgement from the OpenID server that the
    supplied URL is, indeed controlled by the requesting agent.
    '''
    def __init__(self, message, signed_fields=None, claimed_id=None):
        self.message = message
        self.signed_fields = signed_fields or []
        self.claimed_id = claimed_id or self.getSigned(OPENID2_NS, 'claimed_id')

    def isOpenID1(self):
        """Was this authentication response an OpenID 1 authentication
        response?
        """
        return self.message.isOpenID1()

    def isSigned(self, ns_uri, ns_key):
        """Return whether a particular key is signed, regardless of
        its namespace alias
        """
        return self.message.getKey(ns_uri, ns_key) in self.signed_fields

    def getSigned(self, ns_uri, ns_key, default=None):
        """Return the specified signed field if available,
        otherwise return default
        """
        if self.isSigned(ns_uri, ns_key):
            return self.message.getArg(ns_uri, ns_key, default)
        else:
            return default

    def getSignedNS(self, ns_uri):
        """Get signed arguments from the response message.  Return a
        dict of all arguments in the specified namespace.  If any of
        the arguments are not signed, return None.
        """
        msg_args = self.message.getArgs(ns_uri)

        for key in msg_args.keys():
            if not self.isSigned(ns_uri, key):
                return None

        return msg_args

    def extensionResponse(self, namespace_uri, require_signed):
        """Return response arguments in the specified namespace.

        @param namespace_uri: The namespace URI of the arguments to be
        returned.

        @param require_signed: True if the arguments should be among
        those signed in the response, False if you don't care.

        If require_signed is True and the arguments are not signed,
        return None.
        """
        if require_signed:
            return self.getSignedNS(namespace_uri)
        else:
            return self.message.getArgs(namespace_uri)

    def getReturnTo(self):
        """Get the openid.return_to argument from this response.

        This is useful for verifying that this request was initiated
        by this consumer.

        @returns: The return_to URL supplied to the server on the
            initial request, or C{None} if the response did not contain
            an C{openid.return_to} argument.

        @returntype: str
        """
        return self.getSigned(OPENID_NS, 'return_to')

    def __eq__(self, other):
        return (
            (self.endpoint == other.endpoint) and
            (self.message == other.message) and
            (self.signed_fields == other.signed_fields) and
            (self.status == other.status))

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        return '<%s.%s id=%r signed=%r>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            self.identity(), self.signed_fields)
