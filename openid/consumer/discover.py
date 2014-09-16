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


class Service(object):
    """Object representing an OpenID service endpoint.

    @ivar identity_url: the verified identifier.
    @ivar canonicalID: For XRI, the persistent identifier.
    """

    def __init__(self, types=None, server_url=None, claimed_id=None, local_id=None):
        self.types = types if types is not None else [OPENID_2_0_TYPE]
        self.server_url = server_url
        self.claimed_id = claimed_id
        self.local_id = local_id

    @classmethod
    def as_op_identifier(cls, op_endpoint_url):
        return cls([OPENID_IDP_2_0_TYPE], op_endpoint_url)

    def uses_extension(self, extension_uri):
        return extension_uri in self.types

    def ns(self):
        return OPENID1_NS if self.compat_mode() else OPENID2_NS

    def compat_mode(self):
        return not (OPENID_IDP_2_0_TYPE in self.types or OPENID_2_0_TYPE in self.types)

    def is_op_identifier(self):
        return OPENID_IDP_2_0_TYPE in self.types

    def identity(self):
        '''
        Return the identifier that should be sent as the
        openid.identity parameter to the server.
        '''
        return self.local_id or self.claimed_id

    def __str__(self):
        return '<%s server_url=%s claimed_id=%s local_id=%s>' % (
            self.__class__.__name__,
            self.server_url,
            self.claimed_id,
            self.local_id,
        )


def parse_html(url, html):
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
        service = Service(
            [type_uri],
            op_endpoint_url,
            url,
            html_parse.findFirstHref(link_attrs, local_id_rel),
        )
        services.append(service)

    return services


def findOPLocalIdentifier(service_element, types):
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

    @param types: The xrd:Type values present in this service
        element. This function could extract them, but higher level
        code needs to do that anyway.
    @type types: [str]

    @raises DiscoveryFailure: when discovery fails.

    @returns: The OP-Local Identifier for this service element, if one
        is present, or None otherwise.
    @rtype: str or unicode or NoneType
    """
    # XXX: Test this function on its own!

    # Build the list of tags that could contain the OP-Local Identifier
    local_id_tags = []
    if (OPENID_1_1_TYPE in types or
        OPENID_1_0_TYPE in types):
        local_id_tags.append(xrds.nsTag(OPENID_1_0_NS, 'Delegate'))

    if OPENID_2_0_TYPE in types:
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


def parse_service(service_element, user_id, canonicalID=None):
    result = Service(xrds.getTypeURIs(service_element), xrds.getURI(service_element))
    if not result.is_op_identifier():
        result.claimed_id = canonicalID or user_id
        result.local_id = findOPLocalIdentifier(service_element, result.types)
    return result


def parse_xrds(user_id, data):
    et = xrds.parseXRDS(data)
    if xri.is_iname(user_id):
        canonicalID = xrds.getCanonicalID(user_id, et)
        if canonicalID is None:
            raise xrds.XRDSError('No canonicalID found for XRI %r' % user_id)
    else:
        canonicalID = None
    services = [
        parse_service(element, user_id, canonicalID)
        for element in xrds.get_elements(data, SERVICE_TYPES)
    ]
    # Return only OP Identifier services if present or all of them otherwise.
    # Services are ordered by their type according to SERVICE_TYPES list.
    services.sort(key=lambda s: min(SERVICE_TYPES.index(t) for t in s.types))
    op_idp_services = [s for s in services if s.is_op_identifier()]
    return op_idp_services or services


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
    url =  PROXY_URL + xri.toURINormal(iname)[6:] + '?' + urllib.parse.urlencode(query)
    url, data = yadis.fetch_data(url)
    try:
        endpoints = parse_xrds(iname, data)
    except xrds.XRDSError as e:
        logging.exception(e)
        endpoints = []

    return iname, endpoints


def discoverURI(url):
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            # checking both scheme and netloc as things like 'server:80/' put 'server' in scheme
            url = 'http://' + url
        url = urinorm.urinorm(url)
        url = urllib.parse.urldefrag(url)[0]
    except ValueError:
        raise DiscoveryFailure('Normalizing identifier: %s' % url)
    url, data = yadis.fetch_data(url)
    try:
        services = parse_xrds(url, data)
    except xrds.XRDSError:
        services = parse_html(url, data)
    return url, services


def discover(identifier):
    if xri.is_iname(identifier):
        return discoverXRI(identifier)
    else:
        return discoverURI(identifier)
