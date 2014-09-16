"""
ElementTree interface to an XRD document.
"""

import sys
import random
import functools

from datetime import datetime
from time import strptime

from openid import xri
try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import cElementTree as ET


class XRDSError(Exception):
    '''
    General error with the XRDS document.
    '''
    pass


class XRDSFraud(XRDSError):
    """Raised when there's an assertion in the XRDS that it does not have
    the authority to make.
    """


def parseXRDS(text):
    """Parse the given text as an XRDS document.

    @return: ElementTree containing an XRDS document

    @raises XRDSError: When there is a parse error or the document does
        not contain an XRDS.
    """
    try:
        root = ET.XML(text)
    except ET.ParseError:
        raise XRDSError('Error parsing document as XML', text)
    if root.tag != root_tag:
        raise XRDSError('Not an XRDS document', text)
    return ET.ElementTree(root)


XRD_NS_2_0 = 'xri://$xrd*($v*2.0)'
XRDS_NS = 'xri://$xrds'
OPENID_1_0_NS = 'http://openid.net/xmlns/1.0'


def nsTag(ns, t):
    return '{%s}%s' % (ns, t)


def mkXRDTag(t):
    """basestring -> basestring

    Create a tag name in the XRD 2.0 XML namespace suitable for using
    with ElementTree
    """
    return nsTag(XRD_NS_2_0, t)


def mkXRDSTag(t):
    """basestring -> basestring

    Create a tag name in the XRDS XML namespace suitable for using
    with ElementTree
    """
    return nsTag(XRDS_NS, t)

# Tags that are used in Yadis documents
root_tag = mkXRDSTag('XRDS')
service_tag = mkXRDTag('Service')
xrd_tag = mkXRDTag('XRD')
type_tag = mkXRDTag('Type')
uri_tag = mkXRDTag('URI')
expires_tag = mkXRDTag('Expires')

# Other XRD tags
canonicalID_tag = mkXRDTag('CanonicalID')


def getYadisXRD(xrd_tree):
    """Return the XRD element that should contain the Yadis services"""
    xrd = None

    # for the side-effect of assigning the last one in the list to the
    # xrd variable
    for xrd in xrd_tree.findall(xrd_tag):
        pass

    # There were no elements found, or else xrd would be set to the
    # last one
    if xrd is None:
        raise XRDSError('No XRD present in tree')

    return xrd


def getCanonicalID(iname, xrd_tree):
    """Return the CanonicalID from this XRDS document.

    @param iname: the XRI being resolved.
    @type iname: unicode

    @param xrd_tree: The XRDS output from the resolver.
    @type xrd_tree: ElementTree

    @returns: The XRI CanonicalID or None.
    @returntype: unicode or None
    """
    xrd_list = xrd_tree.findall(xrd_tag)
    xrd_list.reverse()

    try:
        canonicalID = xri.XRI(xrd_list[0].findall(canonicalID_tag)[0].text)
    except IndexError:
        return None

    childID = canonicalID.lower()

    for xrd in xrd_list[1:]:
        # XXX: can't use rsplit until we require python >= 2.4.
        parent_sought = childID[:childID.rindex('!')]
        parent = xri.XRI(xrd.findtext(canonicalID_tag))
        if parent_sought != parent.lower():
            raise XRDSFraud("%r can not come from %s" % (childID, parent))

        childID = parent_sought

    root = xri.rootAuthority(iname)
    if not xri.providerIsAuthoritative(root, childID):
        raise XRDSFraud("%r can not come from root %r" % (childID, root))

    return canonicalID


def getLocalID(service_element, is_v1, is_v2):
    # Build the list of tags that could contain the OP-Local Identifier
    local_id_tags = []
    if is_v1:
        local_id_tags.append(nsTag(OPENID_1_0_NS, 'Delegate'))
    if is_v2:
        local_id_tags.append(nsTag(XRD_NS_2_0, 'LocalID'))

    # Walk through all the matching tags and make sure that they all
    # have the same value
    local_id = None
    for local_id_tag in local_id_tags:
        for local_id_element in service_element.findall(local_id_tag):
            if local_id is None:
                local_id = local_id_element.text
            elif local_id != local_id_element.text:
                format = 'More than one %r tag found in one service element'
                message = format % (local_id_tag,)
                raise XRDSError(message)

    return local_id


@functools.total_ordering
class _Max(object):
    """
    Value that compares greater than any other value.

    Should only be used as a singleton. Implemented for use as a
    priority value for when a priority is not specified.
    """
    def __lt__(self, other):
        return isinstance(other, self.__class__)

    def __eq__(self, other):
        return isinstance(other, self.__class__)

Max = _Max()


def getPriorityStrict(element):
    """Get the priority of this element.

    Raises ValueError if the value of the priority is invalid. If no
    priority is specified, it returns a value that compares greater
    than any other value.
    """
    prio_str = element.get('priority')
    if prio_str is not None:
        prio_val = int(prio_str)
        if prio_val >= 0:
            return prio_val
        else:
            raise ValueError('Priority values must be non-negative integers')

    # Any errors in parsing the priority fall through to here
    return Max


def getPriority(element):
    """Get the priority of this element

    Returns Max if no priority is specified or the priority value is invalid.
    """
    try:
        return getPriorityStrict(element)
    except ValueError:
        return Max


def prioSort(elements):
    """Sort a list of elements that have priority attributes"""
    # Randomize the services before sorting so that equal priority
    # elements are load-balanced.
    random.shuffle(elements)

    sorted_elems = sorted(elements, key=getPriority)
    return sorted_elems


def iterServices(xrd_tree):
    """Return an iterable over the Service elements in the Yadis XRD

    sorted by priority"""
    xrd = getYadisXRD(xrd_tree)
    return prioSort(xrd.findall(service_tag))


def getURI(service_element):
    """Given a Service element, return content of its URI tag or
    None if absent
    """
    uri_element = service_element.find(uri_tag)
    return uri_element.text if uri_element is not None else None


def getTypeURIs(service_element):
    """Given a Service element, return a list of the contents of all
    Type tags"""
    return [type_element.text for type_element
            in service_element.findall(type_tag)]


def matches_types(element, types):
    '''
    Checks if the service element supports any of the types.
    '''
    return not types or set(types).intersection(set(getTypeURIs(element)))


def get_elements(data, types):
    '''
    Parses an XRDS document and returns a list of service elements matching
    types.
    '''
    elements = iterServices(parseXRDS(data))
    return [e for e in elements if matches_types(e, types) and getURI(e) is not None]
