import cgi
import io

from openid import fetchers
from openid.yadis import etxrd
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

def _yadis_location(response, body):
    '''
    Checks if the HTTP response refers to a Yadis document in its
    headers or in the HTML meta.

    Returns the location found or None.
    '''
    location = response.getheader('X-XRDS-Location')
    if location:
        return location
    content_type = response.getheader('content-type') or ''
    encoding = cgi.parse_header(content_type)[1].get('charset', 'utf-8')
    content = body.decode(encoding, 'replace')
    try:
        return findHTMLMeta(io.StringIO(content))
    except MetaNotFound:
        pass

def _fetch_text(uri):
    '''
    Fetches the unparsed text of the Yadis document.
    '''
    response = fetchers.fetch(uri, headers={'Accept': 'application/xrds+xml'})
    text = response.read() # MAX_RESPONSE
    location = _yadis_location(response, text)
    if location:
        return _fetch_text(location)
    return text

def discover(uri):
    '''
    Discovers an XRDS document using Yadis protocol.

    Returns DiscoveryResult with the original request uri, a response
    text and a parsed instance of the document if it is indeed an XRDS.
    '''
    text = _fetch_text(uri)
    try:
        xrds = etxrd.parseXRDS(text)
    except etxrd.XRDSError:
        xrds = None
    return DiscoveryResult(uri, text, xrds)
