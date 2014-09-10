import cgi
import io

from openid import fetchers, xrds
from openid.yadis.parsehtml import MetaNotFound, findHTMLMeta


version_info = (2, 0, 0)
__version__ = ".".join(str(x) for x in version_info)


class DiscoveryFailure(Exception):
    """Raised when a YADIS protocol error occurs in the discovery process"""
    identity_url = None

    def __init__(self, message, http_response):
        Exception.__init__(self, message)
        self.http_response = http_response


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


def fetch_data(uri):
    '''
    Fetches the unparsed text of the Yadis document.
    '''
    response = fetchers.fetch(uri, headers={'Accept': 'application/xrds+xml'})
    text = response.read() # MAX_RESPONSE
    location = _yadis_location(response, text)
    if location:
        return fetch_data(location)
    return response.url, text


def matches_types(element, types):
    return not types or \
           set(types).intersection(set(xrds.getTypeURIs(element)))


def endpoints(types, constructor, yadis_url, elements):
    elements = [e for e in elements if matches_types(e, types)]
    for element in elements:
        uris = xrds.sortedURIs(element)
        yield from (constructor(uri, yadis_url, element) for uri in uris)


def parse(url, types, constructor):
    final_url, data = fetch_data(url)
    et = xrds.parseXRDS(data)
    return list(endpoints(types, constructor, final_url, xrds.iterServices(et)))
