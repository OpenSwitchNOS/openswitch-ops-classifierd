# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Vtysh auto-generated typed exceptions module.

.. warning::

   This is auto-generated, do not modify manually!!
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

# from re import match VM
from re import search
from re import sub
from collections import OrderedDict


class VtyshException(Exception):
    """
    Base exception class for vtysh shell errors.

    :param str output: The shell output that triggered this exception.
    """
    def __init__(self, output):
        super(VtyshException, self).__init__()
        self.output = output


class UnknownVtyshException(VtyshException):
    """
    Generic exception raised when the specific exception could not be
    determined.
    """

{% for exception, matches in spec.items() %}
class {{ exception }}(VtyshException):
    """
    This is a typed exception that will be raised when any of the following
    regular expressions match the output of a command:

    ::

        {%- for expression in matches %}
        {{ expression }}
        {%- endfor %}

    """

{% endfor %}
VTYSH_EXCEPTIONS = OrderedDict([
    {%- for exception, matches in spec.items() %}
    (
        {{ exception }},
        [
            {%- for expression in matches %}
            '{{ expression }}',
            {%- endfor %}
        ]
    ),
    {%- endfor %}
])


def determine_exception(output):
    """
    Determine which exception to raise from shell error message.

    :param str output: The shell output error.
    :rtype: VtyshException subclass.
    :return: The corresponding exception class for given message.
    """
    output = sub('[%]+', '', output)
    output = output.strip().lower()
    for exc, matches in VTYSH_EXCEPTIONS.items():
        for expression in matches:
            if search(expression, output):
                return exc
    return UnknownVtyshException


__all__ = [
    'VtyshException',
    'UnknownVtyshException',
{%- for exception in spec.keys() %}
    '{{ exception }}',
{%- endfor %}
    'VTYSH_EXCEPTIONS',
    'determine_exception'
]
{# #}
