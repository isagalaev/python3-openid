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
    '''
    Yadis discovery result:

    - `uri`: original request uri
    - `text`: full response text
    - `xrds`: parsed tree, if `text` is an XRDS document
    '''
    def __init__(self, uri, text, xrds):
        self.uri = uri
        self.text = text
        self.xrds = xrds


def discover(uri, original_uri=None):
    '''
    Discovers an XRDS document using Yadis protocol.

    Returns DiscoveryResult with the original request uri, a response
    text and a parsed instance of the document if it is indeed an XRDS.

    The `result` argument is used internally for recursion.
    '''
    response = fetchers.fetch(uri, headers={'Accept': YADIS_ACCEPT_HEADER})
    text = response.read() # MAX_RESPONSE
    location = whereIsYadis(response, text)
    if location:
        return discover(location, uri)
    try:
        xrds = etxrd.parseXRDS(text)
    except etxrd.XRDSError:
        xrds = None
    return DiscoveryResult(original_uri or uri, text, xrds)

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
