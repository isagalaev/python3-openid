import cgi
import io

from openid import fetchers, xrds
from openid.yadis.parsehtml import MetaNotFound, findHTMLMeta


version_info = (2, 0, 0)
__version__ = ".".join(str(x) for x in version_info)


class DiscoveryFailure(Exception):
    pass


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
    Fetches unparsed text of the Yadis document.
    Returns the URL after redirects and the text
    '''
    response = fetchers.fetch(uri, headers={'Accept': 'application/xrds+xml'})
    text = response.read() # MAX_RESPONSE
    location = _yadis_location(response, text)
    if location:
        text = fetchers.fetch(location).read() # MAX_RESPONSE
    return response.url, text


def matches_types(element, types):
    '''
    Checks if the service element supports any of the types.
    '''
    return not types or \
           set(types).intersection(set(xrds.getTypeURIs(element)))


def _service_uris(elements, types):
    '''
    Generates endpoint data from service elements of given types in
    the form of (service_uri, yadis_url, service_element).
    '''
    elements = [e for e in elements if matches_types(e, types)]
    for element in elements:
        uris = xrds.sortedURIs(element)
        yield from ((uri, element) for uri in uris)


def parse(data, types):
    '''
    Fetches and parses an XRDS document from url and returns a list
    of endpoints.

    '''
    elements = xrds.iterServices(xrds.parseXRDS(data))
    return list(_service_uris(elements, types))
