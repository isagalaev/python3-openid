from functools import partial

from openid import xrds
from openid.yadis.discover import fetch_data, DiscoveryFailure


def matches_types(element, types):
    return not types or \
           set(types).intersection(set(xrds.getTypeURIs(element)))


def filter_services(types, constructor, yadis_url, elements):
    elements = [e for e in elements if matches_types(e, types)]
    result = []
    for element in elements:
        uris = xrds.sortedURIs(element)
        endpoints = [constructor(uri, yadis_url, element) for uri in uris]
        result.extend(endpoints)
    return result


def parse_services(url, types, constructor):
    final_url, data = fetch_data(url)
    et = xrds.parseXRDS(data)
    return filter_services(types, constructor, final_url, xrds.iterServices(et))
