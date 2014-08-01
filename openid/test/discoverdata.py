"""Module to make discovery data test cases available"""
import urllib.parse
import os.path

from openid.yadis.discover import DiscoveryResult, DiscoveryFailure
from openid.yadis.constants import YADIS_HEADER_NAME

tests_dir = os.path.dirname(__file__)
data_path = os.path.join(tests_dir, 'data')


def getDataName(*components):
    sanitized = []
    for part in components:
        if part in ['.', '..']:
            raise ValueError
        elif part:
            sanitized.append(part)

    if not sanitized:
        raise ValueError

    return os.path.join(data_path, *sanitized)


def getExampleXRDS():
    filename = getDataName('example-xrds.xml')
    with open(filename) as f:
        return f.read()

example_xrds = getExampleXRDS()
default_test_file = getDataName('test1-discover.txt')

discover_tests = {}


def readTests(filename):
    with open(filename) as f:
        data = f.read()
    tests = {}
    for case in data.split('\f\n'):
        (name, content) = case.split('\n', 1)
        tests[name] = content
    return tests


def getData(filename, name):
    global discover_tests
    try:
        file_tests = discover_tests[filename]
    except KeyError:
        file_tests = discover_tests[filename] = readTests(filename)
    return file_tests[name]


def fillTemplate(test_name, template, base_url, example_xrds):
    mapping = [
        ('URL_BASE/', base_url),
        ('<XRDS Content>', example_xrds),
        ('YADIS_HEADER', YADIS_HEADER_NAME),
        ('NAME', test_name),
        ]

    for k, v in mapping:
        template = template.replace(k, v)

    return template


def generateSample(test_name, base_url,
                   example_xrds=example_xrds,
                   filename=default_test_file):
    try:
        template = getData(filename, test_name)
    except IOError as why:
        import errno
        if int(why) == errno.ENOENT:
            raise KeyError(filename)
        else:
            raise

    return fillTemplate(test_name, template, base_url, example_xrds)


def generateResult(base_url, input_name, id_name, result_name, success):
    input_url = urllib.parse.urljoin(base_url, input_name)

    result = generateSample(result_name, base_url)
    headers, content = result.split('\n\n', 1)
    content = content.encode('utf-8')
    header_lines = headers.split('\n')
    for header_line in header_lines:
        if header_line.startswith('Content-Type:'):
            _, ctype = header_line.split(':', 1)
            ctype = ctype.strip()
            break
    else:
        ctype = None

    id_url = urllib.parse.urljoin(base_url, id_name)

    result = DiscoveryResult(input_url)
    result.normalized_uri = id_url
    result.xrds_uri = urllib.parse.urljoin(base_url, result_name) if success else None
    result.content_type = ctype
    result.response_text = content
    return input_url, result
