import sys
import os.path
import warnings
import unittest


def specialCaseTests():
    """
    Some modules have an explicit `test` function that collects tests --
    collect these together as a suite.
    """
    function_test_modules = [
        'cryptutil',
        'oidutil',
        'dh',
    ]

    suite = unittest.TestSuite()
    for module_name in function_test_modules:
        module_name = 'openid.test.' + module_name
        try:
            test_mod = __import__(module_name, {}, {}, [None])
        except ImportError:
            print(('Failed to import test %r' % (module_name,)))
        else:
            suite.addTest(unittest.FunctionTestCase(test_mod.test))

    return suite


def pyUnitTests():
    """
    Aggregate unit tests from modules, including a few special cases, and
    return a suite.
    """
    test_module_names = [
        'server',
        'consumer',
        'message',
        'symbol',
        'xrds',
        'xri',
        'association_response',
        'auth_request',
        'negotiation',
        'sreg',
        'ax',
        'pape',
        'pape_draft2',
        'pape_draft5',
        'rpverify',
        'extension',
        'yadis',
        'fetchers',
        'discover',
        'urinorm',
    ]

    test_modules = [
        __import__('openid.test.test_{}'.format(name), {}, {}, ['unused'])
        for name in test_module_names
        ]

    try:
        from openid.test import test_examples
    except ImportError:
        # This is very likely due to twill being unimportable, since it's
        # ancient and unmaintained. Until the examples are reimplemented using
        # something else, we just need to skip it
        warnings.warn("Could not import twill; skipping test_examples.")
    else:
        test_modules.append(test_examples)

    # Some modules have data-driven tests, and they use custom methods
    # to build the test suite -- the module-level pyUnitTests function should
    # return an appropriate test suite
    custom_module_names = [
        'kvform',
        'oidutil',
        'storetest',
        'test_association',
        'test_htmldiscover',
        'test_nonce',
        'trustroot',
        ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for m in test_modules:
        suite.addTest(loader.loadTestsFromModule(m))

    for name in custom_module_names:
        mod = __import__('openid.test.{}'.format(name), {}, {}, ['unused'])
        try:
            suite.addTest(mod.pyUnitTests())
        except AttributeError:
            # because the AttributeError doesn't actually say which
            # object it was.
            print(("Error loading tests from %s:" % (name,)))
            raise

    return suite


def test_suite():
    """
    Collect all of the tests together in a single suite.
    """
    combined_suite = unittest.TestSuite()
    combined_suite.addTests(specialCaseTests())
    combined_suite.addTests(pyUnitTests())
    return combined_suite
