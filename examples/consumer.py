#!/usr/bin/env python
"""
Simple example for an OpenID consumer.

Once you understand this example you'll know the basics of OpenID
and using the Python OpenID library. You can then move on to more
robust examples, and integrating OpenID into your application.
"""
__copyright__ = 'Copyright 2005-2008, Janrain, Inc.'

from http.cookies import SimpleCookie
import cgi
import urllib.parse
import cgitb
import sys


def quoteattr(s):
    """
    Helper to quote attributes in HTML.
    """
    qs = cgi.escape(s, 1)
    return '"{}"'.format(s)

from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import openid
except ImportError:
    sys.stderr.write("""
Failed to import the OpenID library. In order to use this example, you
must either install the library (see INSTALL in the root of the
distribution) or else add the library to python's import path (the
PYTHONPATH environment variable).

For more information, see the README in the root of the library
distribution.""")
    sys.exit(1)

from openid.store import memstore
from openid.store import filestore
from openid.consumer import consumer
from openid.oidutil import appendArgs
from openid.cryptutil import randomString
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
from openid.extensions import pape, sreg

# Used with an OpenID provider affiliate program.
OPENID_PROVIDER_NAME = 'MyOpenID'
OPENID_PROVIDER_URL ='https://www.myopenid.com/affiliate_signup?affiliate_id=39'


class OpenIDHTTPServer(HTTPServer):
    """
    HTTP server that contains a reference to an OpenID consumer and
    knows its base URL.
    """
    def __init__(self, store, *args, **kwargs):
        super(OpenIDHTTPServer, self).__init__(*args, **kwargs)
        self.sessions = {}
        self.store = store

        if self.server_port != 80:
            self.base_url = 'http://{}:{}/'.format(self.server_name,
                                                   self.server_port)
        else:
            self.base_url = 'http://{}/'.format(self.server_name)


class OpenIDRequestHandler(BaseHTTPRequestHandler):
    """
    Request handler that knows how to verify an OpenID identity.
    """
    SESSION_COOKIE_NAME = 'python-openid-session'

    session = None

    def getConsumer(self, stateless=False):
        """
        Return a Consumer instance, optionally bound to a store if `stateless`
        is False (the default).
        """
        if stateless:
            store = None
        else:
            store = self.server.store
        return consumer.Consumer(self.getSession(), store)

    def getSession(self):
        """
        Return the existing session or a new session.
        """
        if self.session is not None:
            return self.session

        # Get value of cookie header that was sent
        cookie_str = self.headers.get('Cookie')
        if cookie_str:
            cookie_obj = SimpleCookie(cookie_str)
            sid_morsel = cookie_obj.get(self.SESSION_COOKIE_NAME, None)
            if sid_morsel is not None:
                sid = sid_morsel.value
            else:
                sid = None
        else:
            sid = None

        # If a session id was not set, create a new one
        if sid is None:
            sid = randomString(16, '0123456789abcdef')
            session = None
        else:
            session = self.server.sessions.get(sid)

        # If no session exists for this session ID, create one
        if session is None:
            session = self.server.sessions[sid] = {}

        session['id'] = sid
        self.session = session
        return session

    def setSessionCookie(self):
        """
        Ensure the session cookie is set by sending the Set-Cookie header.
        """
        sid = self.getSession()['id']
        session_cookie = '%s=%s;' % (self.SESSION_COOKIE_NAME, sid)
        self.send_header('Set-Cookie', session_cookie)

    def do_GET(self):
        """
        Dispatching logic. There are three paths defined:

          / - Display an empty form asking for an identity URL to
              verify
          /verify - Handle form submission, initiating OpenID verification
          /process - Handle a redirect from an OpenID server

        Any other path gets a 404 response. This function also parses
        the query parameters.

        If an exception occurs in this function, a traceback is
        written to the requesting browser.
        """
        try:
            self.parsed_uri = urllib.parse.urlparse(self.path)
            self.query = {}
            for k, v in cgi.parse_qsl(self.parsed_uri[4]):
                self.query[k] = v

            path = self.parsed_uri[2]
            if path == '/':
                self.render()
            elif path == '/verify':
                self.doVerify()
            elif path == '/process':
                self.doProcess()
            elif path == '/affiliate':
                self.doAffiliate()
            else:
                self.notFound()

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.setSessionCookie()
            self.end_headers()
            # Format the traceback and write it to the output
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))

    def doVerify(self):
        """
        Process the form submission, initating OpenID verification.
        """

        # First, make sure that the user entered something
        openid_url = self.query.get('openid_identifier')
        if not openid_url:
            self.render('Enter an OpenID Identifier to verify.',
                        css_class='error', form_contents=openid_url)
            return

        immediate = 'immediate' in self.query
        use_sreg = 'use_sreg' in self.query
        use_pape = 'use_pape' in self.query
        use_stateless = 'use_stateless' in self.query
        oidconsumer = self.getConsumer(stateless=use_stateless)
        try:
            request = oidconsumer.begin(openid_url)
        except consumer.DiscoveryFailure as exc:
            fetch_error_string = 'Error in discovery: %s' % (
                cgi.escape(str(exc)))
            self.render(fetch_error_string,
                        css_class='error',
                        form_contents=openid_url)
        else:
            if request is None:
                msg = 'No OpenID services found for <code>%s</code>' % (
                    cgi.escape(openid_url),)
                self.render(msg, css_class='error', form_contents=openid_url)
            else:
                # Then, ask the library to begin the authorization.
                # Here we find out the identity server that will verify the
                # user's identity, and get a token that allows us to
                # communicate securely with the identity server.
                if use_sreg:
                    self.requestRegistrationData(request)

                if use_pape:
                    self.requestPAPEDetails(request)

                trust_root = self.server.base_url
                return_to = self.buildURL('process')
                if request.shouldSendRedirect():
                    redirect_url = request.redirectURL(
                        trust_root, return_to, immediate=immediate)
                    self.send_response(302)
                    self.send_header('Location', redirect_url)
                    self.writeUserHeader()
                    self.end_headers()
                else:
                    form_html = request.htmlMarkup(
                        trust_root, return_to,
                        form_tag_attrs={'id': 'openid_message'},
                        immediate=immediate)

                    self.wfile.write(bytes(form_html, 'utf-8'))

    def requestRegistrationData(self, request):
        """
        Add the Simple Registration (SREG) extension to the request.
        """
        sreg_request = sreg.SRegRequest(
            required=['nickname'], optional=['fullname', 'email'])
        request.addExtension(sreg_request)

    def requestPAPEDetails(self, request):
        """
        Add the Provider Authentication Policy Extension (PAPE) to the request.
        """
        pape_request = pape.Request([pape.AUTH_PHISHING_RESISTANT])
        request.addExtension(pape_request)

    def doProcess(self):
        """
        Handle the redirect from the OpenID server.
        """
        oidconsumer = self.getConsumer()

        # Ask the library to check the response that the server sent
        # us.  Status is a code indicating the response type. info is
        # either None or a string containing more information about
        # the return type.
        url = 'http://{}{}'.format(self.headers.get('Host'), self.path)
        info = oidconsumer.complete(self.query, url)

        sreg_resp = None
        pape_resp = None
        css_class = 'error'
        display_identifier = info.getDisplayIdentifier()

        if info.status == consumer.FAILURE and display_identifier:
            # In the case of failure, if info is non-None, it is the
            # URL that we were verifying. We include it in the error
            # message to help the user figure out what happened.
            fmt = "Verification of {} failed: {}"
            message = fmt.format(cgi.escape(display_identifier), info.message)
        elif info.status == consumer.SUCCESS:
            # Success means that the transaction completed without
            # error. If info is None, it means that the user cancelled
            # the verification.
            css_class = 'alert'

            # This is a successful verification attempt. If this
            # was a real application, we would do our login,
            # comment posting, etc. here.
            fmt = "You have successfully verified %s as your identity."
            message = fmt % (cgi.escape(display_identifier),)
            sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
            pape_resp = pape.Response.fromSuccessResponse(info)
            if info.endpoint.canonicalID:
                # You should authorize i-name users by their canonicalID,
                # rather than their more human-friendly identifiers.  That
                # way their account with you is not compromised if their
                # i-name registration expires and is bought by someone else.
                message += "  This is an i-name, "
                message += "and its persistent ID is {}".format(
                    cgi.escape(info.endpoint.canonicalID))
        elif info.status == consumer.CANCEL:
            # cancelled
            message = 'Verification cancelled'
        elif info.status == consumer.SETUP_NEEDED:
            if info.setup_url:
                message = '<a href={}>Setup needed</a>'.format(
                    quoteattr(info.setup_url))
            else:
                # This means auth didn't succeed, but you're welcome to try
                # non-immediate mode.
                message = 'Setup needed'
        else:
            # Either we don't understand the code or there is no
            # openid_url included with the error. Give a generic
            # failure message. The library should supply debug
            # information in a log.
            message = 'Verification failed.'

        self.render(message, css_class, display_identifier,
                    sreg_data=sreg_resp, pape_data=pape_resp)

    def doAffiliate(self):
        """
        Direct the user to sign up with an affiliate OpenID provider.

        TODO: Disable this, as JanRain will be sunsetting MyOpenID in Feb 2014.
        """
        sreg_req = sreg.SRegRequest(['nickname'], ['fullname', 'email'])
        href = sreg_req.toMessage().toURL(OPENID_PROVIDER_URL)

        message = """Get an OpenID at <a href=%s>%s</a>""" % (
            quoteattr(href), OPENID_PROVIDER_NAME)
        self.render(message)

    def renderSREG(self, sreg_data):
        """
        Pretty-print the available SREG data.
        """
        if not sreg_data:
            self.wfile.write(
                b'<div class="alert">No registration data was returned</div>')
        else:
            sreg_list = list(sreg_data.items())
            sreg_list.sort()
            self.wfile.write(bytes('<h2>Registration Data</h2>'
                '<table class="sreg">'
                '<thead><tr><th>Field</th><th>Value</th></tr></thead>'
                '<tbody>', 'utf-8'))

            odd = ' class="odd"'
            for k, v in sreg_list:
                field_name = sreg.data_fields.get(k, k)
                value = cgi.escape(v.encode('UTF-8'))
                self.wfile.write(
                    bytes('<tr{}><td>{}</td><td>{}</td></tr>'.format(
                            odd, field_name, value),
                          'utf-8'))
                if odd:
                    odd = ''
                else:
                    odd = ' class="odd"'

            self.wfile.write(bytes('</tbody></table>', 'utf-8'))

    def renderPAPE(self, pape_data):
        """
        Pretty-print the available PAPE data.
        """
        if not pape_data:
            self.wfile.write(
                b'<div class="alert">No PAPE data was returned</div>')
        else:
            self.wfile.write(
                b'<div class="alert">Effective Auth Policies<ul>')

            for policy_uri in pape_data.auth_policies:
                self.wfile.write(
                    bytes(
                        '<li><tt>{}</tt></li>'.format(cgi.escape(policy_uri)),
                        'utf-8'))

            if not pape_data.auth_policies:
                self.wfile.write(b'<li>No policies were applied.</li>')

            self.wfile.write(b'</ul></div>')

    def buildURL(self, action, **query):
        """
        Build a URL relative to the server base_url, with the given
        query parameters added.
        """
        base = urllib.parse.urljoin(self.server.base_url, action)
        return appendArgs(base, query)

    def notFound(self):
        """Render a page with a 404 return code and a message."""
        fmt = 'The path <q>%s</q> was not understood by this server.'
        msg = fmt % (self.path,)
        openid_url = self.query.get('openid_identifier')
        self.render(msg, 'error', openid_url, status=404)

    def render(self, message=None, css_class='alert', form_contents=None,
               status=200, title="Python OpenID Consumer Example",
               sreg_data=None, pape_data=None):
        """Render a page."""
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.pageHeader(title)
        if message:
            self.wfile.write(
                "<div class='{}'>".format(css_class).encode('utf-8'))
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write("</div>".encode('utf-8'))

        if sreg_data is not None:
            self.renderSREG(sreg_data)

        if pape_data is not None:
            self.renderPAPE(pape_data)

        self.pageFooter(form_contents)

    def pageHeader(self, title):
        """Render the page header"""
        self.setSessionCookie()
        self.wfile.write(bytes('''<html>
  <head><title>%s</title></head>
  <style type="text/css">
      * {
        font-family: verdana,sans-serif;
      }
      body {
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      tr.odd td {
        background-color: #dddddd;
      }
      table.sreg {
        border: 1px solid black;
        border-collapse: collapse;
      }
      table.sreg th {
        border-bottom: 1px solid black;
      }
      table.sreg td, table.sreg th {
        padding: 0.5em;
        text-align: left;
      }
      table {
        margin: 0;
        padding: 0;
      }
      .alert {
        border: 1px solid #e7dc2b;
        background: #fff888;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
      }
      #verify-form {
        border: 1px solid #777777;
        background: #dddddd;
        margin-top: 1em;
        padding-bottom: 0em;
      }
  </style>
  <body>
    <h1>%s</h1>
    <p>
      This example consumer uses the <a href=
      "http://github.com/openid/python-openid" >Python
      OpenID</a> library. It just verifies that the identifier that you enter
      is your identifier.
    </p>''' % (title, title), 'UTF-8'))

    def pageFooter(self, form_contents):
        """Render the page footer"""
        if not form_contents:
            form_contents = ''
        self.wfile.write(bytes('''\
    <div id="verify-form">
      <form method="get" accept-charset="UTF-8" action=%s>
        Identifier:
        <input type="text" name="openid_identifier" value=%s />
        <input type="submit" value="Verify" /><br />
        <input type="checkbox" name="immediate" id="immediate" /><label for="immediate">Use immediate mode</label>
        <input type="checkbox" name="use_sreg" id="use_sreg" /><label for="use_sreg">Request registration data</label>
        <input type="checkbox" name="use_pape" id="use_pape" /><label for="use_pape">Request phishing-resistent auth policy (PAPE)</label>
        <input type="checkbox" name="use_stateless" id="use_stateless" /><label for="use_stateless">Use stateless mode</label>
      </form>
    </div>
  </body>
</html>
''' % (quoteattr(self.buildURL('verify')), quoteattr(form_contents)), 'UTF-8'))


def main(host, port, data_path, weak_ssl=False):
    """
    Start the sample server.
    """
    # Instantiate OpenID consumer store and OpenID consumer.  If you
    # were connecting to a database, you would create the database
    # connection and instantiate an appropriate store here.
    if data_path:
        store = filestore.FileOpenIDStore(data_path)
    else:
        store = memstore.MemoryStore()

    if weak_ssl:
        setDefaultFetcher(Urllib2Fetcher())

    addr = (host, port)
    server = OpenIDHTTPServer(store, addr, OpenIDRequestHandler)

    print('Server running at:')
    print(server.base_url)
    server.serve_forever()

if __name__ == '__main__':
    host = 'localhost'
    port = 8001
    weak_ssl = False

    import optparse

    parser = optparse.OptionParser('Usage:\n %prog [options]')
    parser.add_option(
        '-d', '--data-path', dest='data_path',
        help='Data directory for storing OpenID consumer state. '
        'Setting this option implies using a "FileStore."')
    parser.add_option(
        '-p', '--port', dest='port', type='int', default=port,
        help='Port on which to listen for HTTP requests. '
        'Defaults to port %default.')
    parser.add_option(
        '-s', '--host', dest='host', default=host,
        help='Host on which to listen for HTTP requests. '
        'Also used for generating URLs. Defaults to %default.')
    parser.add_option(
        '-w', '--weakssl', dest='weakssl', default=False,
        action='store_true', help='Skip ssl cert verification')

    options, args = parser.parse_args()
    if args:
        parser.error('Expected no arguments. Got %r' % args)

    host = options.host
    port = options.port
    data_path = options.data_path
    weak_ssl = options.weakssl

    main(host, port, data_path, weak_ssl)
