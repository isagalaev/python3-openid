import cgi

import html5lib

from openid import fetchers


HEADER = 'x-xrds-location'


def http_equiv(content):
    root = html5lib.parse(content)
    for meta in root.findall('{http://www.w3.org/1999/xhtml}head/{http://www.w3.org/1999/xhtml}meta'):
        if meta.get('http-equiv', '').lower() == HEADER:
            return meta.get('content')


def _yadis_location(response, body):
    '''
    Checks if the HTTP response refers to a Yadis document in its
    headers or in the HTML meta.

    Returns the location found or None.
    '''
    location = response.getheader(HEADER)
    if location:
        return location
    content_type = response.getheader('content-type') or ''
    encoding = cgi.parse_header(content_type)[1].get('charset', 'utf-8')
    content = body.decode(encoding, 'replace')
    return http_equiv(content)


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
