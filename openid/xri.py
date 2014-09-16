# -*- test-case-name: openid.test.test_xri -*-
"""Utility functions for handling XRIs.

@see: XRI Syntax v2.0 at the U{OASIS XRI Technical Committee<http://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xri>}
"""

import re
import urllib.parse
from functools import reduce


XRI_AUTHORITIES = ['!', '=', '@', '+', '$', '(']
XREF_RE = re.compile(r'\((.*?)\)')

def is_iname(identifier):
    return identifier.startswith(tuple(['xri://'] + XRI_AUTHORITIES))


def _escape_xref(match):
    '''
    Escape things that need to be escaped if they're in a cross-reference.
    '''
    return match.group(0).replace('/', '%2F') .replace('?', '%3F') .replace('#', '%23')


def urlescape(xri):
    '''
    Escapes an unprefixed xri to be used as part of a URL.
    '''
    xri = urllib.parse.quote(xri, safe=''.join(XRI_AUTHORITIES + [')', '/', '?', '#', '*']))
    xri = XREF_RE.sub(_escape_xref, xri)
    return xri


def providerIsAuthoritative(providerID, canonicalID):
    """Is this provider ID authoritative for this XRI?

    @returntype: bool
    """
    # XXX: can't use rsplit until we require python >= 2.4.
    lastbang = canonicalID.rindex('!')
    parent = canonicalID[:lastbang]
    return parent == providerID


def rootAuthority(xri):
    """Return the root authority for an XRI.

    Example::

        rootAuthority("xri://@example") == "xri://@"

    @type xri: unicode
    @returntype: unicode
    """
    if xri.startswith('xri://'):
        xri = xri[6:]
    authority = xri.split('/', 1)[0]
    if authority[0] == '(':
        # Cross-reference.
        # XXX: This is incorrect if someone nests cross-references so there
        #   is another close-paren in there.  Hopefully nobody does that
        #   before we have a real xriparse function.  Hopefully nobody does
        #   that *ever*.
        root = authority[:authority.index(')') + 1]
    elif authority[0] in XRI_AUTHORITIES:
        # Other XRI reference.
        root = authority[0]
    else:
        # IRI reference.  XXX: Can IRI authorities have segments?
        segments = authority.split('!')
        segments = reduce(list.__add__,
            [s.split('*') for s in segments])
        root = segments[0]

    return XRI(root)


def XRI(xri):
    """An XRI object allowing comparison of XRI.

    Ideally, this would do full normalization and provide comparsion
    operators as per XRI Syntax.  Right now, it just does a bit of
    canonicalization by ensuring the xri scheme is present.

    @param xri: an xri string
    @type xri: unicode
    """
    if not xri.startswith('xri://'):
        xri = 'xri://' + xri
    return xri
