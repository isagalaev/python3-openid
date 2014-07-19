'''
Wrapper around urlopen providing default parameters and safety checkings.
'''
import urllib.request
import urllib.error
import urllib.parse
import sys

import openid


USER_AGENT = 'python-openid/%s (%s) Python-urllib/%s' % (
    openid.__version__,
    sys.platform,
    urllib.request.__version__,
)


def fetch(url, body=None, headers=None):
    if urllib.parse.urlparse(url).scheme not in ('http', 'https'):
        raise urllib.error.URLError('Bad URL scheme: %r' % url)

    if headers is None:
        headers = {}
    headers.setdefault('User-Agent', USER_AGENT)

    request = urllib.request.Request(url, data=body, headers=headers)
    return urllib.request.urlopen(request)
