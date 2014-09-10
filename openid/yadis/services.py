from openid import xrds
from openid.yadis.discover import fetch_data


def matches_types(element, types):
    return not types or \
           set(types).intersection(set(xrds.getTypeURIs(element)))


def endpoints(types, constructor, yadis_url, elements):
    elements = [e for e in elements if matches_types(e, types)]
    for element in elements:
        uris = xrds.sortedURIs(element)
        yield from (constructor(uri, yadis_url, element) for uri in uris)


def parse(url, types, constructor):
    final_url, data = fetch_data(url)
    et = xrds.parseXRDS(data)
    return list(endpoints(types, constructor, final_url, xrds.iterServices(et)))
