# -*- test-case-name: openid.test.test_xrires -*-
"""XRI resolution.
"""
from urllib.parse import urlencode
import urllib.error
import logging

from openid import fetchers, xri, xrds


DEFAULT_PROXY = 'http://proxy.xri.net/'


class ProxyResolver(object):
    """Python interface to a remote XRI proxy resolver.
    """
    def __init__(self, proxy_url=DEFAULT_PROXY):
        self.proxy_url = proxy_url


    def queryURL(self, url, service_type=None):
        """Build a URL to query the proxy resolver.

        @param xri: An XRI to resolve.
        @type xri: unicode

        @param service_type: The service type to resolve, if you desire
            service endpoint selection.  A service type is a URI.
        @type service_type: str

        @returns: a URL
        @returntype: str
        """
        # Trim off the xri:// prefix.  The proxy resolver didn't accept it
        # when this code was written, but that may (or may not) change for
        # XRI Resolution 2.0 Working Draft 11.
        qxri = xri.toURINormal(url)[6:]
        hxri = self.proxy_url + qxri
        args = {
            # XXX: If the proxy resolver will ensure that it doesn't return
            # bogus CanonicalIDs (as per Steve's message of 15 Aug 2006
            # 11:13:42), then we could ask for application/xrd+xml instead,
            # which would give us a bit less to process.
            '_xrd_r': 'application/xrds+xml',
            }
        if service_type:
            args['_xrd_t'] = service_type
        else:
            # Don't perform service endpoint selection.
            args['_xrd_r'] += ';sep=false'
        query = _appendArgs(hxri, args)
        return query


    def query(self, xri, service_types):
        """Resolve some services for an XRI.

        May raise urllib.error.URLError or L{xrds.XRDSError} if
        the fetching or parsing don't go so well.

        @param xri: An XRI to resolve.
        @type xri: unicode

        @param service_types: A list of services types to query for.  Service
            types are URIs.
        @type service_types: list of str

        @returns: tuple of (CanonicalID, Service elements)
        @returntype: (unicode, list of C{ElementTree.Element}s)
        """
        # FIXME: No test coverage!
        services = []
        # Make a seperate request to the proxy resolver for each service
        # type, as, if it is following Refs, it could return a different
        # XRDS for each.

        canonicalID = None

        for service_type in service_types:
            url = self.queryURL(xri, service_type)
            try:
                response = fetchers.fetch(url)
                et = xrds.parseXRDS(response.read()) # MAX_RESPONSE
                canonicalID = xrds.getCanonicalID(xri, et)
                some_services = xrds.iterServices(et)
                some_services = [s for s in some_services if service_type in xrds.getTypeURIs(s)]
                services.extend(some_services)
            except urllib.error.HTTPError as e:
                logging.warning(str(e))
        # TODO:
        #  * If we do get hits for multiple service_types, we're almost
        #    certainly going to have duplicated service entries and
        #    broken priority ordering.
        return canonicalID, services


def _appendArgs(url, args):
    """Append some arguments to an HTTP query.
    """
    # to be merged with oidutil.appendArgs when we combine the projects.
    if hasattr(args, 'items'):
        args = list(args.items())
        args.sort()

    if len(args) == 0:
        return url

    # According to XRI Resolution section "QXRI query parameters":
    #
    # """If the original QXRI had a null query component (only a leading
    #    question mark), or a query component consisting of only question
    #    marks, one additional leading question mark MUST be added when
    #    adding any XRI resolution parameters."""

    if '?' in url.rstrip('?'):
        sep = '&'
    else:
        sep = '?'

    return '%s%s%s' % (url, sep, urlencode(args))