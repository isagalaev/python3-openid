import warnings
import unittest
from unittest import mock
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlunparse
import io

from openid import fetchers

from .support import HTTPResponse

# XXX: make these separate test cases


def _assertEqual(v1, v2, extra):
    try:
        assert v1 == v2
    except AssertionError:
        raise AssertionError("%r != %r ; context %r" % (v1, v2, extra))


def failUnlessResponseExpected(expected, actual, extra):
    _assertEqual(expected.url, actual.url, extra)
    _assertEqual(expected.status, actual.status, extra)
    _assertEqual(expected.read(), actual.read(), extra)
    actual_headers = {k.lower(): v for k, v in actual.headers.items()}
    expected_headers = {k.lower(): v for k, v in expected.headers.items()}
    del actual_headers['date']
    del actual_headers['server']
    del actual_headers['content-length']
    _assertEqual(actual_headers, expected_headers, extra)


def urlopen(request, data=None):
    DATA = {
        '/success': (200, None),
        '/badreq': (400, None),
        '/server_error': (500, None),
    }

    if isinstance(request, str):
        request = urllib.request.Request(request)

    url = request.get_full_url()
    schema, server, path, params, query, fragment = urlparse(url)
    if path not in DATA:
        raise urllib.error.HTTPError(url, 404, '', {}, io.BytesIO(b'Not found'))
    status, location = DATA[path]
    if 400 <= status:
        raise urllib.error.HTTPError(url, status, '', {}, io.BytesIO())
    body = b'/success'
    headers = {
        'Server': 'Urlopen-Mock',
        'Date': 'Mon, 21 Jul 2014 19:52:42 GMT',
        'Content-type': 'text/plain',
        'Content-length': len(body),
    }
    return HTTPResponse(url, status, headers, body)


@mock.patch('urllib.request.urlopen', urlopen)
def test_fetcher():

    def geturl(path):
        return 'http://unittest%s' % path

    paths = ['/success']
    for path in paths:
        expected = HTTPResponse(geturl('/success'), 200, {'content-type': 'text/plain'}, b'/success')
        fetch_url = geturl(path)
        try:
            actual = fetchers.fetch(fetch_url)
        except (SystemExit, KeyboardInterrupt):
            pass
        except Exception as e:
            raise AssertionError((fetch_url, e))
        else:
            failUnlessResponseExpected(expected, actual, extra=locals())

    for err_url in [
            'http://invalid.janrain.com/',
            'not:a/url',
            'ftp://janrain.com/pub/',
            'file://localhost/thing.txt',
            'ftp://server/path',
            'sftp://server/path',
            'ssh://server/path',
            geturl('/notfound'),
            geturl('/badreq'),
            geturl('/forbidden'),
            geturl('/error'),
            geturl('/server_error'),
        ]:
        try:
            result = fetchers.fetch(err_url)
        except urllib.error.URLError:
            pass
        else:
            assert False, 'An exception was expected, got result %r' % result


def test():
    test_fetcher()


def pyUnitTests():
    return unittest.TestSuite([
        unittest.FunctionTestCase(test),
    ])
