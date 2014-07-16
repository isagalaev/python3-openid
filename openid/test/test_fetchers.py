import warnings
import unittest
import urllib.request
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from openid import fetchers

# XXX: make these separate test cases


def _assertEqual(v1, v2, extra):
    try:
        assert v1 == v2
    except AssertionError:
        raise AssertionError("%r != %r ; context %r" % (v1, v2, extra))


def failUnlessResponseExpected(expected, actual, extra):
    _assertEqual(expected.final_url, actual.final_url, extra)
    _assertEqual(expected.status, actual.status, extra)
    _assertEqual(expected.body, actual.body, extra)
    got_headers = dict(actual.headers)

    del got_headers['date']
    del got_headers['server']

    for k, v in expected.headers.items():
        assert got_headers[k] == v, (k, v, got_headers[k], extra)


def test_fetcher(server):

    def geturl(path):
        host, port = server.server_address
        return 'http://%s:%s%s' % (host, port, path)

    expected_headers = {'content-type': 'text/plain'}

    def plain(path, code):
        path = '/' + path
        expected = fetchers.HTTPResponse(
            geturl(path), code, expected_headers, path.encode('utf-8'))
        return (path, expected)

    expect_success = fetchers.HTTPResponse(
        geturl('/success'), 200, expected_headers, b'/success')
    cases = [
        ('/success', expect_success),
        ('/301redirect', expect_success),
        ('/302redirect', expect_success),
        ('/303redirect', expect_success),
        ('/307redirect', expect_success),
        plain('notfound', 404),
        plain('badreq', 400),
        plain('forbidden', 403),
        plain('error', 500),
        plain('server_error', 503),
        ]

    for path, expected in cases:
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
