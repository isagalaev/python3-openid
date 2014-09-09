"""This module contains functions and classes used for extracting
endpoint information out of a Yadis XRD file using the ElementTree XML
parser.
"""
import collections
from functools import partial

from openid import xrds


class BasicServiceEndpoint(object):
    """Generic endpoint object that contains parsed service
    information, as well as a reference to the service element from
    which it was generated. If there is more than one xrd:Type or
    xrd:URI in the xrd:Service, this object represents just one of
    those pairs.

    This object can be used as a filter, because it implements
    fromBasicServiceEndpoint.

    The simplest kind of filter you can write implements
    fromBasicServiceEndpoint, which takes one of these objects.
    """
    def __init__(self, yadis_url, type_uris, uri, service_element):
        self.type_uris = type_uris
        self.yadis_url = yadis_url
        self.uri = uri
        self.service_element = service_element

    def matchTypes(self, type_uris):
        """Query this endpoint to see if it has any of the given type
        URIs. This is useful for implementing other endpoint classes
        that e.g. need to check for the presence of multiple versions
        of a single protocol.

        @param type_uris: The URIs that you wish to check
        @type type_uris: iterable of str

        @return: all types that are in both in type_uris and
            self.type_uris
        """
        return [uri for uri in type_uris if uri in self.type_uris]

    def fromBasicServiceEndpoint(endpoint):
        """Trivial transform from a basic endpoint to itself. This
        method exists to allow BasicServiceEndpoint to be used as a
        filter.

        If you are subclassing this object, re-implement this function.

        @param endpoint: An instance of BasicServiceEndpoint
        @return: The object that was passed in, with no processing.
        """
        return endpoint

    fromBasicServiceEndpoint = staticmethod(fromBasicServiceEndpoint)


class IFilter(object):
    """Interface for Yadis filter objects. Other filter-like things
    are convertable to this class."""

    def getServiceEndpoints(self, yadis_url, service_element):
        """Returns an iterator of endpoint objects"""
        raise NotImplementedError


def filter_endpoints(pred, yadis_url, service_element):
    """Returns an iterator of endpoint objects produced by the
    filter functions."""
    endpoints = [
        BasicServiceEndpoint(yadis_url, types, uri, service_element)
        for types, uri, _ in xrds.expandService(service_element)
    ]
    endpoints = [pred(e) for e in endpoints]
    return [e for e in endpoints if e is not None]


def mkFilter(source):
    """Convert a filter-convertable thing into a filter

    @param source: an endpoint or a callable
    """
    if source is None:
        source = BasicServiceEndpoint

    if hasattr(source, 'fromBasicServiceEndpoint'):
        # It's an endpoint object, so put its endpoint
        # conversion attribute into the list of endpoint
        # transformers
        func = source.fromBasicServiceEndpoint
    elif isinstance(source, collections.Callable):
        # It's a simple callable, so add it to the list of
        # endpoint transformers
        func = source
    else:
        raise TypeError('Filter source is neither an endpoint nor a callable')

    return partial(filter_endpoints, func)
