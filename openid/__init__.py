#-*-coding: utf-8-*-
"""
This is an implementation of the OpenID specification in Python.  It contains
code for both server and consumer implementations.

See the :ref:`openid.consumer.consumer` module for consumer implementations,
and the :ref:`openid.server.server` module for server implementations.

Source code is on GitHub at http://github.com/necaris/python3-openid/

(C) 2005-2008 JanRain, Inc., 2012-2014 Rami Chowdhury, and contributors

.. code-block:: none

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions
    and limitations under the License.
"""

version_info = (3, 0, 4)

__version__ = ".".join(str(x) for x in version_info)

__all__ = [
    'association',
    'consumer',
    'cryptutil',
    'dh',
    'extension',
    'extensions',
    'fetchers',
    'kvform',
    'message',
    'oidutil',
    'server',
    'sreg',
    'store',
    'urinorm',
    'yadis',
]
