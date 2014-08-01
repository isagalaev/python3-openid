# -*- test-case-name: openid.test.test_yadis_discover -*-
__all__ = ['discover', 'DiscoveryResult', 'DiscoveryFailure']

from io import StringIO
import urllib.error

from openid import fetchers
from openid.yadis import etxrd
from openid.yadis.constants import \
     YADIS_HEADER_NAME, YADIS_CONTENT_TYPE, YADIS_ACCEPT_HEADER
from openid.yadis.parsehtml import MetaNotFound, findHTMLMeta

class DiscoveryFailure(Exception):
    """Raised when a YADIS protocol error occurs in the discovery process"""
    identity_url = None

    def __init__(self, message, http_response):
        Exception.__init__(self, message)
        self.http_response = http_response

class DiscoveryResult(object):
    """Contains the result of performing Yadis discovery on a URI"""
    # Normalized request uri
    uri = None

    # The URI from which the response text was returned (set to
    # None if there was no XRDS document found)
    xrds_uri = None

    # The document returned from the xrds_uri
    response_text = None

    def __init__(self, uri):
        self.uri = uri

    def isXRDS(self):
        return self.xrds_uri is not None


def is_xrds(body):
    try:
        et = etxrd.parseXRDS(body)
        return True
    except etxrd.XRDSError:
        return False

def discover(uri):
    """Discover services for a given URI.

    @param uri: The identity URI as a well-formed http or https
        URI. The well-formedness and the protocol are not checked, but
        the results of this function are undefined if those properties
        do not hold.

    @return: DiscoveryResult object
    """
    resp = fetchers.fetch(uri, headers={'Accept': YADIS_ACCEPT_HEADER})
    result = DiscoveryResult(resp.url)
    result.response_text = resp.read() # MAX_RESPONSE
    if is_xrds(result.response_text):
        result.xrds_uri = result.uri
        return result
    location = whereIsYadis(resp, result.response_text)
    return discover(location) if location else result

def whereIsYadis(resp, body):
    """Given a HTTPResponse, return the location of the Yadis document.

    May be the URL just retrieved, another URL, or None if no suitable URL can
    be found.

    [non-blocking]

    @returns: str or None
    """
    # Attempt to find out where to go to discover the document
    # or if we already have it
    content_type = resp.getheader('content-type')

    # According to the spec, the content-type header must be an exact
    # match, or else we have to look for an indirection.
    if (content_type and
        content_type.split(';', 1)[0].lower() == YADIS_CONTENT_TYPE):
        return resp.url
    else:
        # Try the header
        yadis_loc = resp.getheader(YADIS_HEADER_NAME)

        if not yadis_loc:
            # Parse as HTML if the header is missing.
            #
            # XXX: do we want to do something with content-type, like
            # have a whitelist or a blacklist (for detecting that it's
            # HTML)?

            # Decode body by encoding of file
            content_type = content_type or ''
            encoding = content_type.rsplit(';', 1)
            if (len(encoding) == 2 and
                    encoding[1].strip().startswith('charset=')):
                encoding = encoding[1].split('=', 1)[1].strip()
            else:
                encoding = 'utf-8'

            try:
                content = body.decode(encoding)
            except UnicodeError:
                # All right, the detected encoding has failed. Try with
                # UTF-8 (even if there was no detected encoding and we've
                # defaulted to UTF-8, it's not that expensive an operation)
                try:
                    content = body.decode('utf-8')
                except UnicodeError:
                    # At this point the content cannot be decoded to a str
                    # using the detected encoding or falling back to utf-8,
                    # so we have to resort to replacing undecodable chars.
                    # This *will* result in broken content but there isn't
                    # anything else that can be done.
                    content = body.decode(encoding, 'replace')

            try:
                yadis_loc = findHTMLMeta(StringIO(content))
            except (MetaNotFound, UnicodeError):
                # UnicodeError: Response body could not be encoded and xrds
                # location could not be found before troubles occur.
                pass

        return yadis_loc
