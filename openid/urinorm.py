import re
import urllib.parse


uri_illegal_char_re = re.compile(
    "[^-A-Za-z0-9:/?#[\]@!$&'()*+,;=._~%]", re.UNICODE)

authority_re = re.compile(r'^([^@]*@)?([^:]*)(:.*)?')

pct_encoded_pattern = r'%([0-9A-Fa-f]{2})'
pct_encoded_re = re.compile(pct_encoded_pattern)

_unreserved = [False] * 256
for _ in range(ord('A'), ord('Z') + 1): _unreserved[_] = True
for _ in range(ord('0'), ord('9') + 1): _unreserved[_] = True
for _ in range(ord('a'), ord('z') + 1): _unreserved[_] = True
_unreserved[ord('-')] = True
_unreserved[ord('.')] = True
_unreserved[ord('_')] = True
_unreserved[ord('~')] = True

ASCII = ''.join(map(chr, range(256)))


def _pct_encoded_replace_unreserved(mo):
    try:
        i = int(mo.group(1), 16)
        if _unreserved[i]:
            return chr(i)
        else:
            return mo.group().upper()

    except ValueError:
        return mo.group()


def remove_dot_segments(path):
    result_segments = []

    while path:
        if path.startswith('../'):
            path = path[3:]
        elif path.startswith('./'):
            path = path[2:]
        elif path.startswith('/./'):
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
        elif path == '..' or path == '.':
            path = ''
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
    scheme, authority, path, params, query, fragment = urllib.parse.urlparse(uri)
    scheme = scheme.lower()
    authority = authority.lower()
    path, params, query, fragment = map(quote, (path, params, query, fragment))

    if not scheme or not authority or scheme not in ('http', 'https'):
        raise ValueError('Not an absolute HTTP or HTTPS URI: %s' % uri)

    if not authority_re.match(authority):
        raise ValueError('URI does not have a valid authority: %s' % uri)

    # This should've been simply authority.encode(..).decode(..) but idna breaks on
    # anythong starting with '.' so we have to encode it in chunks
    authority = '.'.join(chunk.encode('idna').decode('ascii') for chunk in authority.split('.'))
    if ':' in authority:
        host, port = authority.split(':', 1)
        if not port or (scheme, port) in [('http', '80'), ('https', '443')]:
            authority = host

    path = pct_encoded_re.sub(_pct_encoded_replace_unreserved, path)
    path = remove_dot_segments(path)
    if not path:
        path = '/'

    uri = urllib.parse.urlunparse((scheme, authority, path, params, query, fragment))
    illegal_mo = uri_illegal_char_re.search(uri)
    if illegal_mo:
        raise ValueError('Illegal characters in URI: %r at position %s' %
                         (illegal_mo.group(), illegal_mo.start()))
    return uri
