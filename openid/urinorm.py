import re
import urllib.parse


ILLEGAL_CHAR_RE = re.compile("[^-A-Za-z0-9:/?#[\]@!$&'()*+,;=._~%]", re.UNICODE)
HOST_PORT_RE = re.compile(r'^[A-Za-z0-9\.]+(:\d+)?(/|$)')
PCT_ENCODED_RE = re.compile(r'%([0-9A-Fa-f]{2})')
UNRESERVED = '-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
ASCII = ''.join(map(chr, range(256)))


def _pct_encoded_replace_unreserved(mo):
    c = chr(int(mo.group(1), 16))
    if c in UNRESERVED:
        return c
    return mo.group().upper()


def remove_dot_segments(path):
    result_segments = []

    while path:
        if path.startswith('/./'):
            path = path[2:]
        elif path == '/.':
            path = '/'
        elif path.startswith('/../'):
            path = path[3:]
            if result_segments:
                result_segments.pop()
        elif path == '/..':
            path = '/'
            if result_segments:
                result_segments.pop()
        else:
            i = 0
            if path[0] == '/':
                i = 1
            i = path.find('/', i)
            if i == -1:
                i = len(path)
            result_segments.append(path[:i])
            path = path[i:]

    return ''.join(result_segments)


def quote(s):
    return urllib.parse.quote(s, safe=ASCII)


def urinorm(uri):
    '''
    Normalize a URI
    '''
    # prepend URL in the form 'server' or 'server:port' with the scheme as
    # urlparse doesn't do what we expect
    if HOST_PORT_RE.match(uri):
        uri = 'http://' + uri
    scheme, authority, path, params, query, fragment = urllib.parse.urlparse(uri)
    scheme = scheme.lower()
    authority = authority.lower()
    path, params, query, fragment = map(quote, (path, params, query, fragment))

    if not scheme:
        scheme = 'http'
    if not authority or scheme not in ('http', 'https'):
        raise ValueError('Not an absolute HTTP or HTTPS URI: %s' % uri)

    # This should've been simply authority.encode(..).decode(..) but idna breaks on
    # anythong starting with '.' so we have to encode it in chunks
    authority = '.'.join(chunk.encode('idna').decode('ascii') for chunk in authority.split('.'))
    if ':' in authority:
        host, port = authority.split(':', 1)
        if not port or (scheme, port) in [('http', '80'), ('https', '443')]:
            authority = host

    path = PCT_ENCODED_RE.sub(_pct_encoded_replace_unreserved, path)
    path = remove_dot_segments(path)
    if not path:
        path = '/'

    uri = urllib.parse.urlunparse((scheme, authority, path, params, query, fragment))
    match = ILLEGAL_CHAR_RE.search(uri)
    if match:
        raise ValueError('Illegal characters in URI: %r at position %s' %
                         (match.group(), match.start()))
    return uri
