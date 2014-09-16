# -*- test-case-name: openid.test.test_xri -*-
"""Utility functions for handling XRIs.

@see: XRI Syntax v2.0 at the U{OASIS XRI Technical Committee<http://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xri>}
"""

import re
import urllib.parse
from functools import reduce


AUTHORITIES = ['!', '=', '@', '+', '$', '(']
XREF_RE = re.compile(r'\((.*?)\)')


def unprefix(xri):
    return xri[6:] if xri.startswith('xri://') else xri


def is_iname(identifier):
    return unprefix(identifier).startswith(tuple(AUTHORITIES))


def _escape_xref(match):
    '''
    Escape things that need to be escaped if they're in a cross-reference.
    '''
    return match.group(0).replace('/', '%2F') .replace('?', '%3F') .replace('#', '%23')


def urlescape(xri):
    '''
    Escapes an xri to be used as part of a URL.
    '''
    xri = urllib.parse.quote(xri, safe=''.join(AUTHORITIES + [')', '/', '?', '#', '*']))
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
    '''
    Return the root authority for an XRI:

        rootAuthority("@example") == "@"
    '''
    authority = unprefix(xri).split('/', 1)[0]
    if authority[0] == '(':
        # Cross-reference.
        # XXX: This is incorrect if someone nests cross-references so there
        #   is another close-paren in there.  Hopefully nobody does that
        #   before we have a real xriparse function.  Hopefully nobody does
        #   that *ever*.
        root = authority[:authority.index(')') + 1]
    elif authority[0] in AUTHORITIES:
        # Other XRI reference.
        root = authority[0]
    else:
        # IRI reference.  XXX: Can IRI authorities have segments?
        root = authority.split('!')[0].split('*')[0]

    return root
