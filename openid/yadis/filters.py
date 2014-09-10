"""This module contains functions and classes used for extracting
endpoint information out of a Yadis XRD file using the ElementTree XML
parser.
"""
import collections
from functools import partial

from openid import xrds


def filter_endpoints(pred, yadis_url, service_element):
    """Returns an iterator of endpoint objects produced by the
    filter functions."""
    service_uris = xrds.sortedURIs(service_element) or [None]
    endpoints = [pred(uri, yadis_url, service_element) for uri in service_uris]
    return [e for e in endpoints if e is not None]


def mkFilter(func):
    """Convert a filter-convertable thing into a filter

    @param func: a callable returning an endpoint or None from a service endpoint
    """
    if func is None:
        func = lambda *x: tuple(x)
    return partial(filter_endpoints, func)
