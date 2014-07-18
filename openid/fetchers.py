# -*- test-case-name: openid.test.test_fetchers -*-
"""
This module contains the HTTP fetcher interface and several implementations.
"""

__all__ = ['fetch', 'HTTPResponse']

import urllib.request
import urllib.error
import urllib.parse
import http.client

import sys
import contextlib

import openid


USER_AGENT = "python-openid/%s (%s)" % (openid.__version__, sys.platform)
MAX_RESPONSE_KB = 1024


class HTTPResponse(object):
    """XXX document attributes"""
    headers = None
    status = None
    body = None
    final_url = None

    def __init__(self, final_url=None, status=None, headers=None, body=None):
        self.final_url = final_url
        self.status = status
        self.headers = headers
        self.body = body

    def __repr__(self):
        return "<%s status %s for %s>" % (self.__class__.__name__,
                                          self.status,
                                          self.final_url)


def fetch(url, body=None, headers=None):
    if urllib.parse.urlparse(url).scheme not in ('http', 'https'):
        raise urllib.error.URLError('Bad URL scheme: %r' % url)

    if headers is None:
        headers = {}

    headers.setdefault(
        'User-Agent',
        "%s Python-urllib/%s" % (USER_AGENT, urllib.request.__version__))

    if isinstance(body, str):
        body = bytes(body, encoding="utf-8")

    request = urllib.request.Request(url, data=body, headers=headers)
    f = urllib.request.urlopen(request)
    with contextlib.closing(f):
        return HTTPResponse(
            final_url=f.geturl(),
            status=f.status,
            headers={k.lower(): v for k, v in f.info().items()},
            body=f.read(MAX_RESPONSE_KB * 1024),
        )

