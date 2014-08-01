# -*- test-case-name: openid.test.test_yadis_discover -*-
__all__ = ['discover', 'DiscoveryResult', 'DiscoveryFailure']

import cgi
from io import StringIO
import urllib.error

from openid import fetchers
from openid.yadis import etxrd
from openid.yadis.constants import \
     YADIS_HEADER_NAME, YADIS_CONTENT_TYPE, YADIS_ACCEPT_HEADER
from openid.yadis.parsehtml import MetaNotFound, findHTMLMeta

class DiscoveryFailure(Exception):
    """Raised when a YADIS protocol error occurs in the discovery process"""
    identity_url = None

    def __init__(self, message, http_response):
        Exception.__init__(self, message)
        self.http_response = http_response

class DiscoveryResult(object):
    """Contains the result of performing Yadis discovery on a URI"""
    # Normalized request uri
    uri = None

    # The URI from which the response text was returned (set to
    # None if there was no XRDS document found)
    xrds_uri = None

    # The document returned from the xrds_uri
    response_text = None

    def __init__(self, uri):
        self.uri = uri

    def isXRDS(self):
        return self.xrds_uri is not None


def is_xrds(body):
    try:
        et = etxrd.parseXRDS(body)
        return True
    except etxrd.XRDSError:
        return False

def discover(uri, result=None):
    """Discover services for a given URI.

    @param uri: The identity URI as a well-formed http or https
        URI. The well-formedness and the protocol are not checked, but
        the results of this function are undefined if those properties
        do not hold.

    @return: DiscoveryResult object
    """
    if result is None:
        result = DiscoveryResult(uri)
    resp = fetchers.fetch(uri, headers={'Accept': YADIS_ACCEPT_HEADER})
    result.response_text = resp.read() # MAX_RESPONSE
    if is_xrds(result.response_text):
        result.xrds_uri = uri
        return result
    location = whereIsYadis(resp, result.response_text)
    return discover(location, result) if location else result

def whereIsYadis(resp, body):
    """Given a HTTPResponse, return the location of the Yadis document.

    May be the URL just retrieved, another URL, or None if no suitable URL can
    be found.

    [non-blocking]

    @returns: str or None
    """
    location = resp.getheader(YADIS_HEADER_NAME)
    if location:
        return location

    content_type = resp.getheader('content-type') or ''
    encoding = cgi.parse_header(content_type)[1].get('charset', 'utf-8')
    content = body.decode(encoding, 'replace')
    try:
        return findHTMLMeta(StringIO(content))
    except MetaNotFound:
        pass
