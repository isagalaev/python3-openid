import unittest

import openid.urinorm
from . import support


@support.gentests
class UrinormTest(unittest.TestCase):
    data = [
        ('normal', ('http://example.com/', 'http://example.com/')),
        ('trailing_slash', ('http://example.com', 'http://example.com/')),
        ('empty_port', ('http://example.com:/', 'http://example.com/')),
        ('default_port', ('http://example.com:80/', 'http://example.com/')),
        ('host_case', ('http://wWw.exaMPLE.COm/', 'http://www.example.com/')),
        ('scheme_case', ('htTP://example.com/', 'http://example.com/')),
        ('escape_case', ('http://example.com/foo%2cbar', 'http://example.com/foo%2Cbar')),
        ('path_unescape', ('http://example.com/foo%2Dbar%2dbaz', 'http://example.com/foo-bar-baz')),
        ('path_dots1', ('http://example.com/a/b/c/./../../g', 'http://example.com/a/g')),
        ('path_dots2', ('http://example.com/mid/content=5/../6', 'http://example.com/mid/6')),
        ('single_dot', ('http://example.com/a/./b', 'http://example.com/a/b')),
        ('double_dot', ('http://example.com/a/../b', 'http://example.com/b')),
        ('leading_double_dot', ('http://example.com/../b', 'http://example.com/b')),
        ('trailing_single_dot', ('http://example.com/a/.', 'http://example.com/a/')),
        ('trailing_double_dot', ('http://example.com/a/..', 'http://example.com/')),
        ('trailing_dot_slash', ('http://example.com/a/./', 'http://example.com/a/')),
        ('trailing_dot_dot_slash', ('http://example.com/a/../', 'http://example.com/')),
        ('syntax', ('hTTPS://a/./b/../b/%63/%7bfoo%7d', 'https://a/b/c/%7Bfoo%7D')),
        ('bad_scheme', ('ftp://example.com/', 'fail')),
        ('non_absolute', ('http:/foo', 'fail')),
        ('illegal_chars', ('http://<illegal>.com/', 'fail')),
        ('non_ascii', ('http://foo.com/\u0008', 'fail')),
    ]

    def _test(self, source, expected):
        try:
            actual = openid.urinorm.urinorm(source)
        except ValueError as why:
            self.assertEqual(expected, 'fail', why)
        else:
            self.assertEqual(actual, expected)

if __name__ == '__main__':
    unittest.main()
