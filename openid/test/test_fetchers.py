import warnings
import unittest
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

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
    assert actual_headers == expected_headers


def test_fetcher(server):

    def geturl(path):
        host, port = server.server_address
        return 'http://%s:%s%s' % (host, port, path)

    paths = ['/success', '/301redirect', '/302redirect', '/303redirect', '/307redirect']
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


class FetcherTestHandler(BaseHTTPRequestHandler):
    cases = {
        '/success': (200, None),
        '/301redirect': (301, '/success'),
        '/302redirect': (302, '/success'),
        '/303redirect': (303, '/success'),
        '/307redirect': (307, '/success'),
        '/notfound': (404, None),
        '/badreq': (400, None),
        '/forbidden': (403, None),
        '/error': (500, None),
        '/server_error': (503, None),
        }

    def log_request(self, *args):
        pass

    def do_GET(self):
        try:
            http_code, location = self.cases[self.path]
        except KeyError:
            self.errorResponse('Bad path')
        else:
            extra_headers = [('Content-type', 'text/plain')]
            if location is not None:
                host, port = self.server.server_address
                base = ('http://%s:%s' % (host, port,))
                location = base + location
                extra_headers.append(('Location', location))
            self._respond(http_code, extra_headers, self.path)

    def do_POST(self):
        try:
            http_code, extra_headers = self.cases[self.path]
        except KeyError:
            self.errorResponse('Bad path')
        else:
            if http_code in [301, 302, 303, 307]:
                self.errorResponse()
            else:
                content_type = self.headers.get('content-type', 'text/plain')
                extra_headers.append(('Content-type', content_type))
                content_length = int(self.headers.get('Content-length', '-1'))
                body = self.rfile.read(content_length)
                self._respond(http_code, extra_headers, body)

    def errorResponse(self, message=None):
        req = [
            ('HTTP method', self.command),
            ('path', self.path),
            ]
        if message:
            req.append(('message', message))

        body_parts = ['Bad request:\r\n']
        for k, v in req:
            body_parts.append(' %s: %s\r\n' % (k, v))
        body = ''.join(body_parts)
        self._respond(400, [('Content-type', 'text/plain')], body)

    def _respond(self, http_code, extra_headers, body):
        self.send_response(http_code)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(bytes(body, encoding="utf-8"))

    # def finish(self):
    #     if not self.wfile.closed:
    #         self.wfile.flush()
    #         # self.wfile.close()
    #     # self.rfile.close()


def test():
    host = 'localhost'
    # When I use port 0 here, it works for the first fetch and the
    # next one gets connection refused.  Bummer.  So instead, pick a
    # port that's *probably* not in use.
    import os
    port = (os.getpid() % 31000) + 1024

    server = HTTPServer((host, port), FetcherTestHandler)

    import threading
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()

    test_fetcher(server)

    server.shutdown()


def pyUnitTests():
    return unittest.TestSuite([
        unittest.FunctionTestCase(test),
    ])
