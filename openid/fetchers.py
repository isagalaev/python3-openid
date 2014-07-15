# -*- test-case-name: openid.test.test_fetchers -*-
"""
This module contains the HTTP fetcher interface and several implementations.
"""

__all__ = ['fetch', 'getDefaultFetcher', 'setDefaultFetcher', 'HTTPResponse',
           'HTTPFetcher', 'createHTTPFetcher', 'HTTPFetchingError']

import urllib.request
import urllib.error
import urllib.parse
import http.client

import time
import io
import sys
import contextlib

import openid
import openid.urinorm


USER_AGENT = "python-openid/%s (%s)" % (openid.__version__, sys.platform)
MAX_RESPONSE_KB = 1024


def fetch(url, body=None, headers=None):
    """Invoke the fetch method on the default fetcher. Most users
    should need only this method.

    @raises Exception: any exceptions that may be raised by the default fetcher
    """
    fetcher = getDefaultFetcher()
    return fetcher.fetch(url, body, headers)


def createHTTPFetcher():
    """Create a default HTTP fetcher instance."""
    return Urllib2Fetcher()

# Contains the currently set HTTP fetcher. If it is set to None, the
# library will call createHTTPFetcher() to set it. Do not access this
# variable outside of this module.
_default_fetcher = None


def getDefaultFetcher():
    """Return the default fetcher instance
    if no fetcher has been set, it will create a default fetcher.

    @return: the default fetcher
    @rtype: HTTPFetcher
    """
    global _default_fetcher

    if _default_fetcher is None:
        setDefaultFetcher(createHTTPFetcher())

    return _default_fetcher


def setDefaultFetcher(fetcher, wrap_exceptions=True):
    """Set the default fetcher

    @param fetcher: The fetcher to use as the default HTTP fetcher
    @type fetcher: HTTPFetcher

    @param wrap_exceptions: Whether to wrap exceptions thrown by the
        fetcher wil HTTPFetchingError so that they may be caught
        easier. By default, exceptions will be wrapped. In general,
        unwrapped fetchers are useful for debugging of fetching errors
        or if your fetcher raises well-known exceptions that you would
        like to catch.
    @type wrap_exceptions: bool
    """
    global _default_fetcher
    if fetcher is None or not wrap_exceptions:
        _default_fetcher = fetcher
    else:
        _default_fetcher = ExceptionWrappingFetcher(fetcher)


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


class HTTPFetchingError(Exception):
    """Exception that is wrapped around all exceptions that are raised
    by the underlying fetcher when using the ExceptionWrappingFetcher

    @ivar why: The exception that caused this exception
    """
    def __init__(self, why=None):
        Exception.__init__(self, why)
        self.why = why


class ExceptionWrappingFetcher:
    """Fetcher that wraps another fetcher, causing all exceptions

    @cvar uncaught_exceptions: Exceptions that should be exposed to the
        user if they are raised by the fetch call
    """

    uncaught_exceptions = (SystemExit, KeyboardInterrupt, MemoryError)

    def __init__(self, fetcher):
        self.fetcher = fetcher

    def fetch(self, *args, **kwargs):
        try:
            return self.fetcher.fetch(*args, **kwargs)
        except self.uncaught_exceptions:
            raise
        except:
            exc_cls, exc_inst = sys.exc_info()[:2]
            if exc_inst is None:
                # string exceptions
                exc_inst = exc_cls

            raise HTTPFetchingError(why=exc_inst)


class Urllib2Fetcher:
    """An C{L{HTTPFetcher}} that uses urllib2.
    """

    # Parameterized for the benefit of testing frameworks, see
    # http://trac.openidenabled.com/trac/ticket/85
    urlopen = staticmethod(urllib.request.urlopen)

    def fetch(self, url, body=None, headers=None):
        if not _allowedURL(url):
            raise ValueError('Bad URL scheme: %r' % (url,))

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
            url_resource = self.urlopen(req)
            with contextlib.closing(url_resource):
                return self._makeResponse(url_resource)
        except urllib.error.HTTPError as why:
            with contextlib.closing(why):
                resp = self._makeResponse(why)
                return resp
        except (urllib.error.URLError, http.client.BadStatusLine) as why:
            raise
        except Exception as why:
            raise AssertionError(why)

    def _makeResponse(self, urllib2_response):
        '''
        Construct an HTTPResponse from the the urllib response. Attempt to
        decode the response body from bytes to str if the necessary information
        is available.
        '''
        resp = HTTPResponse()
        resp.body = urllib2_response.read(MAX_RESPONSE_KB * 1024)
        resp.final_url = urllib2_response.geturl()
        resp.headers = self._lowerCaseKeys(
            dict(list(urllib2_response.info().items())))

        if hasattr(urllib2_response, 'code'):
            resp.status = urllib2_response.code
        else:
            resp.status = 200

        return resp

    def _lowerCaseKeys(self, headers_dict):
        new_dict = {}
        for k, v in headers_dict.items():
            new_dict[k.lower()] = v
        return new_dict

    def _parseHeaderValue(self, header_value):
        """
        Parse out a complex header value (such as Content-Type, with a value
        like "text/html; charset=utf-8") into a main value and a dictionary of
        extra information (in this case, 'text/html' and {'charset': 'utf8'}).
        """
        values = header_value.split(';', 1)
        if len(values) == 1:
            # There's no extra info -- return the main value and an empty dict
            return values[0], {}
        main_value, extra_values = values[0], values[1].split(';')
        extra_dict = {}
        for value_string in extra_values:
            try:
                key, value = value_string.split('=', 1)
                extra_dict[key.strip()] = value.strip()
            except ValueError:
                # Can't unpack it -- must be malformed. Ignore
                pass
        return main_value, extra_dict
