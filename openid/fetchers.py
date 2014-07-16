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


def _allowedURL(url):
    parsed = urllib.parse.urlparse(url)
    # scheme is the first item in the tuple
    return parsed[0] in ('http', 'https')

def _makeResponse(urllib2_response):
    '''
    Construct an HTTPResponse from the the urllib response. Attempt to
    decode the response body from bytes to str if the necessary information
    is available.
    '''
    resp = HTTPResponse()
    resp.body = urllib2_response.read(MAX_RESPONSE_KB * 1024)
    resp.final_url = urllib2_response.geturl()
    resp.headers = {k.lower(): v for k, v in urllib2_response.info().items()}

    if hasattr(urllib2_response, 'code'):
        resp.status = urllib2_response.code
    else:
        resp.status = 200

    return resp

def fetch(url, body=None, headers=None):
    if not _allowedURL(url):
        raise urllib.error.URLError('Bad URL scheme: %r' % url)

    if headers is None:
        headers = {}

    headers.setdefault(
        'User-Agent',
        "%s Python-urllib/%s" % (USER_AGENT, urllib.request.__version__))

    if isinstance(body, str):
        body = bytes(body, encoding="utf-8")

    req = urllib.request.Request(url, data=body, headers=headers)

    url_resource = None
    try:
        url_resource = urllib.request.urlopen(req)
        with contextlib.closing(url_resource):
            return _makeResponse(url_resource)
    except urllib.error.HTTPError as why:
        with contextlib.closing(why):
            resp = _makeResponse(why)
            return resp
    except (urllib.error.URLError, http.client.BadStatusLine) as why:
        raise
    except Exception as why:
        raise AssertionError(why)

