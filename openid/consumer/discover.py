'''
Functions to discover OpenID endpoints from identifiers.
'''
import urllib.parse
import logging

from openid import urinorm, yadis, xri, xrds
from openid.consumer import html_parse
from openid.message import OPENID1_NS, OPENID2_NS

OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'
OPENID_IDP_2_0_TYPE = 'http://specs.openid.net/auth/2.0/server'
OPENID_2_0_TYPE = 'http://specs.openid.net/auth/2.0/signon'
OPENID_1_1_TYPE = 'http://openid.net/signon/1.1'
OPENID_1_0_TYPE = 'http://openid.net/signon/1.0'

# OpenID service type URIs, listed in order of preference.  The
# ordering of this list affects yadis and XRI service discovery.
SERVICE_TYPES = [
    OPENID_IDP_2_0_TYPE,
    OPENID_2_0_TYPE,
    OPENID_1_1_TYPE,
    OPENID_1_0_TYPE,
]

PROXY_URL = 'http://proxy.xri.net/'


class DiscoveryFailure(Exception):
    pass


class OpenIDServiceEndpoint(object):
    """Object representing an OpenID service endpoint.

    @ivar identity_url: the verified identifier.
    @ivar canonicalID: For XRI, the persistent identifier.
    """

    def __init__(self):
        self.claimed_id = None
        self.server_url = None
        self.local_id = None
        self.canonicalID = None
        self.iname = None
        self.type_uris = []

    def usesExtension(self, extension_uri):
        return extension_uri in self.type_uris

    def preferredNamespace(self):
        if (OPENID_IDP_2_0_TYPE in self.type_uris or
            OPENID_2_0_TYPE in self.type_uris):
            return OPENID2_NS
        else:
            return OPENID1_NS

    def supportsType(self, type_uri):
        """Does this endpoint support this type?

        I consider C{/server} endpoints to implicitly support C{/signon}.
        """
        return (
            (type_uri in self.type_uris) or
            (type_uri == OPENID_2_0_TYPE and self.isOPIdentifier())
            )

    def display_id(self):
        '''
        iname or claimed_id formatted for readability
        '''
        return self.iname or urllib.parse.urldefrag(self.claimed_id or '').url

    def compatibilityMode(self):
        return self.preferredNamespace() != OPENID2_NS

    def isOPIdentifier(self):
        return OPENID_IDP_2_0_TYPE in self.type_uris

    def parseService(self, yadis_url, uri, service_element):
        """Set the state of this object based on the contents of the
        service element."""
        self.type_uris = xrds.getTypeURIs(service_element)
        self.server_url = uri

        if not self.isOPIdentifier():
            # XXX: This has crappy implications for Service elements
            # that contain both 'server' and 'signon' Types.  But
            # that's a pathological configuration anyway, so I don't
            # think I care.
            self.local_id = findOPLocalIdentifier(service_element,
                                                  self.type_uris)
            self.claimed_id = yadis_url

    def getLocalID(self):
        """Return the identifier that should be sent as the
        openid.identity parameter to the server."""
        return self.local_id or self.canonicalID or self.claimed_id

    @classmethod
    def fromServiceElement(cls, uri, yadis_url, service_element):
        openid_endpoint = cls()
        openid_endpoint.parseService(yadis_url, uri, service_element)
        return openid_endpoint

    def fromHTML(cls, uri, html):
        """Parse the given document as HTML looking for an OpenID <link
        rel=...>

        @rtype: [OpenIDServiceEndpoint]
        """
        discovery_types = [
            (OPENID_2_0_TYPE, 'openid2.provider', 'openid2.local_id'),
            (OPENID_1_1_TYPE, 'openid.server', 'openid.delegate'),
            ]

        link_attrs = html_parse.parseLinkAttrs(html)
        services = []
        for type_uri, op_endpoint_rel, local_id_rel in discovery_types:
            op_endpoint_url = html_parse.findFirstHref(
                link_attrs, op_endpoint_rel)
            if op_endpoint_url is None:
                continue

            service = cls()
            service.claimed_id = uri
            service.local_id = html_parse.findFirstHref(
                link_attrs, local_id_rel)
            service.server_url = op_endpoint_url
            service.type_uris = [type_uri]

            services.append(service)

        return services

    fromHTML = classmethod(fromHTML)


    def fromOPEndpointURL(cls, op_endpoint_url):
        """Construct an OP-Identifier OpenIDServiceEndpoint object for
        a given OP Endpoint URL

        @param op_endpoint_url: The URL of the endpoint
        @rtype: OpenIDServiceEndpoint
        """
        service = cls()
        service.server_url = op_endpoint_url
        service.type_uris = [OPENID_IDP_2_0_TYPE]
        return service

    fromOPEndpointURL = classmethod(fromOPEndpointURL)


    def __str__(self):
        return ("<%s.%s "
                "server_url=%r "
                "claimed_id=%r "
                "local_id=%r "
                "canonicalID=%r "
                ">"
                 % (self.__class__.__module__, self.__class__.__name__,
                    self.server_url,
                    self.claimed_id,
                    self.local_id,
                    self.canonicalID,
                    ))



def findOPLocalIdentifier(service_element, type_uris):
    """Find the OP-Local Identifier for this xrd:Service element.

    This considers openid:Delegate to be a synonym for xrd:LocalID if
    both OpenID 1.X and OpenID 2.0 types are present. If only OpenID
    1.X is present, it returns the value of openid:Delegate. If only
    OpenID 2.0 is present, it returns the value of xrd:LocalID. If
    there is more than one LocalID tag and the values are different,
    it raises a DiscoveryFailure. This is also triggered when the
    xrd:LocalID and openid:Delegate tags are different.

    @param service_element: The xrd:Service element
    @type service_element: ElementTree.Node

    @param type_uris: The xrd:Type values present in this service
        element. This function could extract them, but higher level
        code needs to do that anyway.
    @type type_uris: [str]

    @raises DiscoveryFailure: when discovery fails.

    @returns: The OP-Local Identifier for this service element, if one
        is present, or None otherwise.
    @rtype: str or unicode or NoneType
    """
    # XXX: Test this function on its own!

    # Build the list of tags that could contain the OP-Local Identifier
    local_id_tags = []
    if (OPENID_1_1_TYPE in type_uris or
        OPENID_1_0_TYPE in type_uris):
        local_id_tags.append(xrds.nsTag(OPENID_1_0_NS, 'Delegate'))

    if OPENID_2_0_TYPE in type_uris:
        local_id_tags.append(xrds.nsTag(xrds.XRD_NS_2_0, 'LocalID'))

    # Walk through all the matching tags and make sure that they all
    # have the same value
    local_id = None
    for local_id_tag in local_id_tags:
        for local_id_element in service_element.findall(local_id_tag):
            if local_id is None:
                local_id = local_id_element.text
            elif local_id != local_id_element.text:
                format = 'More than one %r tag found in one service element'
                message = format % (local_id_tag,)
                raise DiscoveryFailure(message)

    return local_id

def getOPOrUserServices(services):
    '''
    Extract OP Identifier services.  If none found, return the
    rest, sorted with most preferred first according to SERVICE_TYPES.

    services is a list of OpenIDServiceEndpoint objects.

    Returns a list of OpenIDServiceEndpoint objects.
    '''
    services.sort(key=lambda s: min(SERVICE_TYPES.index(t) for t in s.type_uris))
    if services and services[0].isOPIdentifier():
        services = [s for s in services if s.isOPIdentifier()]
    return services


def discoverXRI(iname):
    if iname.startswith('xri://'):
        iname = iname[6:]
    query = {
        # XXX: If the proxy resolver will ensure that it doesn't return
        # bogus CanonicalIDs (as per Steve's message of 15 Aug 2006
        # 11:13:42), then we could ask for application/xrd+xml instead,
        # which would give us a bit less to process.
        '_xrd_r': 'application/xrds+xml;sep=false',
    }
    url = PROXY_URL + xri.toURINormal(iname)[6:] + '?' + urllib.parse.urlencode(query)
    try:
        url, data = yadis.fetch_data(url)
        et = xrds.parseXRDS(data)
        endpoints = [OpenIDServiceEndpoint.fromServiceElement(uri, iname, element)
            for uri, element in yadis.parse(data, SERVICE_TYPES)
        ]
        canonicalID = xrds.getCanonicalID(iname, et)
        if canonicalID is None:
            raise xrds.XRDSError('No CanonicalID found for XRI %r' % iname)
    except xrds.XRDSError:
        logging.exception('xrds error on %s' % iname)
        endpoints = []

    for endpoint in endpoints:
        endpoint.canonicalID = canonicalID
        endpoint.claimed_id = canonicalID
        endpoint.iname = iname

    # FIXME: returned xri should probably be in some normal form
    return iname, getOPOrUserServices(endpoints)


def normalizeURL(url):
    '''
    Normalize a URL, converting normalization failures to DiscoveryFailure
    '''
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            # checking both scheme and netloc as things like 'server:80/' put 'server' in scheme
            url = 'http://' + url
        url = urinorm.urinorm(url)
        return urllib.parse.urldefrag(url)[0]
    except ValueError as why:
        raise DiscoveryFailure('Normalizing identifier: %s' % why)


def discoverURI(url):
    url, data = yadis.fetch_data(normalizeURL(url))
    try:
        openid_services = [
            OpenIDServiceEndpoint.fromServiceElement(service_uri, url, element)
            for service_uri, element in yadis.parse(data, SERVICE_TYPES)]
    except xrds.XRDSError:
        openid_services = OpenIDServiceEndpoint.fromHTML(url, data)
    return url, getOPOrUserServices(openid_services)

def discover(identifier):
    if xri.identifierScheme(identifier) == "XRI":
        return discoverXRI(identifier)
    else:
        return discoverURI(identifier)
