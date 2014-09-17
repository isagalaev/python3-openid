"""
ElementTree interface to an XRD document.
"""
from datetime import datetime
try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import cElementTree as ET

from openid import xri


NAMESPACES = {
    'xrd': 'xri://$xrd*($v*2.0)',
    'xrds': 'xri://$xrds',
    'openid': 'http://openid.net/xmlns/1.0',
}


def t(prefixed_name):
    prefix, name = prefixed_name.split(':')
    return '{%s}%s' % (NAMESPACES[prefix], name)


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
    if root.tag != t('xrds:XRDS'):
        raise XRDSError('Not an XRDS document', text)
    return ET.ElementTree(root)


def getCanonicalID(iname, xrd_tree):
    """Return the CanonicalID from this XRDS document.

    @param iname: the XRI being resolved.
    @type iname: unicode

    @param xrd_tree: The XRDS output from the resolver.
    @type xrd_tree: ElementTree

    @returns: The XRI CanonicalID or None.
    @returntype: unicode or None
    """
    xrd_list = xrd_tree.findall(t('xrd:XRD'))
    xrd_list.reverse()

    try:
        canonicalID = xri.unprefix(xrd_list[0].findall(t('xrd:CanonicalID'))[0].text)
    except IndexError:
        return None

    childID = canonicalID.lower()

    for xrd in xrd_list[1:]:
        # XXX: can't use rsplit until we require python >= 2.4.
        parent_sought = childID[:childID.rindex('!')]
        parent = xri.unprefix(xrd.findtext(t('xrd:CanonicalID')))
        if parent_sought != parent.lower():
            raise XRDSFraud("%r can not come from %s" % (childID, parent))

        childID = parent_sought

    root = xri.root_authority(iname)
    if not xri.is_authoritative(root, childID):
        raise XRDSFraud("%r can not come from root %r" % (childID, root))

    return canonicalID


def getLocalID(service_element, is_v1, is_v2):
    # Build the list of tags that could contain the OP-Local Identifier
    local_id_tags = []
    if is_v1:
        local_id_tags.append(t('openid:Delegate'))
    if is_v2:
        local_id_tags.append(t('xrd:LocalID'))

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


def _priority(element):
    '''
    Sort key for elements sorted by priority attribute. Represented as tuple
    to ensure None is sorted after int values.
    '''
    value = element.get('priority')
    return (0, int(value)) if value else (1, 0)


def iterServices(tree):
    """Return an iterable over the Service elements in the Yadis XRD
    sorted by priority"""
    try:
        xrd = tree.findall(t('xrd:XRD'))[-1] # the last XRD element, per spec
    except IndexError:
        raise XRDSError('No XRD elements found')
    elements = xrd.findall(t('xrd:Service'))
    return sorted(elements, key=_priority)


def getURI(service_element):
    """Given a Service element, return content of its URI tag or
    None if absent
    """
    uri_element = service_element.find(t('xrd:URI'))
    return uri_element.text if uri_element is not None else None


def getTypeURIs(service_element):
    """Given a Service element, return a list of the contents of all
    Type tags"""
    return [type_element.text for type_element
            in service_element.findall(t('xrd:Type'))]


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
