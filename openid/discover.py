'''
Functions to discover OpenID endpoints from identifiers.
'''
import urllib.parse
import logging

import html5lib

from openid import urinorm, yadis, xri, xrds
from openid.message import OPENID1_NS, OPENID2_NS

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
    root = html5lib.parse(html)
    links = root.findall('{http://www.w3.org/1999/xhtml}head/{http://www.w3.org/1999/xhtml}link')
    hrefs = {rel: l.get('href') for l in links for rel in l.get('rel', '').split()}

    link_types = [
        (OPENID_2_0_TYPE, 'openid2.provider', 'openid2.local_id'),
        (OPENID_1_1_TYPE, 'openid.server', 'openid.delegate'),
    ]

    return [
        Service([type_uri], hrefs[op_endpoint_rel], url, hrefs.get(local_id_rel))
        for type_uri, op_endpoint_rel, local_id_rel in link_types
        if op_endpoint_rel in hrefs
    ]


def parse_service(service_element, user_id, canonicalID=None):
    result = Service(xrds.getTypeURIs(service_element), xrds.getURI(service_element))
    if not result.is_op_identifier():
        result.claimed_id = canonicalID or user_id
        v1 = OPENID_1_0_TYPE in result.types or OPENID_1_1_TYPE in result.types
        v2 = OPENID_2_0_TYPE in result.types
        result.local_id = xrds.getLocalID(service_element, v1, v2)
    return result


def parse_xrds(user_id, data):
    et = xrds.parseXRDS(data)
    if xri.is_iname(user_id):
        canonicalID = xrds.getCanonicalID(user_id, et)
        if canonicalID is None:
            raise xrds.XRDSError('No canonicalID found for XRI %r' % user_id)
    else:
        canonicalID = None
    return [
        parse_service(element, user_id, canonicalID)
        for element in xrds.get_elements(data, SERVICE_TYPES)
    ]

def discoverXRI(iname):
    iname = xri.unprefix(iname)
    query = {
        # XXX: If the proxy resolver will ensure that it doesn't return
        # bogus CanonicalIDs (as per Steve's message of 15 Aug 2006
        # 11:13:42), then we could ask for application/xrd+xml instead,
        # which would give us a bit less to process.
        '_xrd_r': 'application/xrds+xml;sep=false',
    }
    url =  PROXY_URL + xri.urlescape(iname) + '?' + urllib.parse.urlencode(query)
    url, data = yadis.fetch_data(url)
    try:
        endpoints = parse_xrds(iname, data)
    except xrds.XRDSError as e:
        logging.exception(e)
        endpoints = []

    return endpoints


def discoverURI(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        # checking both scheme and netloc as things like 'server:80/' put 'server' in scheme
        url = 'http://' + url
    url = urinorm.urinorm(url)
    url = urllib.parse.urldefrag(url)[0]
    url, data = yadis.fetch_data(url)
    try:
        services = parse_xrds(url, data)
    except xrds.XRDSError:
        services = parse_html(url, data)
    return services


def discoverall(identifier):
    func = discoverXRI if xri.is_iname(identifier) else discoverURI
    return sorted(func(identifier), key=lambda s: min(SERVICE_TYPES.index(t) for t in s.types if t in SERVICE_TYPES))


def discover(identifier):
    services = discoverall(identifier)
    if not services:
        raise DiscoveryFailure('No services found for %s' % identifier)
    return services[0]

